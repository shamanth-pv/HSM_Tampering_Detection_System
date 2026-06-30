#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <string.h>
#include "hsm_tamper.h"

#define TAMPER_JOURNAL          "tamper_journal.bin"
#define SILENCE_THRESHOLD_MS    2000

// ── NEW: I2C tamper severity levels sent by the host ──────────────────────────
#define I2C_SEVERITY_WARNING    1   // Suspicious but not conclusive
#define I2C_SEVERITY_CRITICAL   2   // Definitive tamper — zeroize immediately
// ─────────────────────────────────────────────────────────────────────────────

static TEE_Time last_heartbeat  = {0, 0};
static int      suspicion_score = 0;
static bool     keys_active     = true;

/* ── Helper: Calculate log count based on file size ────────────────────────── */
static uint32_t get_log_count(void) {
    TEE_ObjectHandle obj;
    TEE_ObjectInfo   info;
    TEE_Result res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE,
                                              TAMPER_JOURNAL, strlen(TAMPER_JOURNAL),
                                              TEE_DATA_FLAG_ACCESS_READ, &obj);
    if (res == TEE_SUCCESS) {
        TEE_GetObjectInfo1(obj, &info);
        TEE_CloseObject(obj);
        return (uint32_t)(info.dataSize / sizeof(uint32_t));
    }
    return 0;
}

/* ── Helper: Append a new event to the Secure Journal ──────────────────────── */
static void append_tamper_log(void) {
    TEE_ObjectHandle obj;
    TEE_Result       res;
    uint32_t         event_marker = 0xDEADBEEF;

    res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE,
                                   TAMPER_JOURNAL, strlen(TAMPER_JOURNAL),
                                   TEE_DATA_FLAG_ACCESS_WRITE | TEE_DATA_FLAG_ACCESS_WRITE_META,
                                   &obj);
    if (res == TEE_ERROR_ITEM_NOT_FOUND) {
        res = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE,
                                         TAMPER_JOURNAL, strlen(TAMPER_JOURNAL),
                                         TEE_DATA_FLAG_ACCESS_WRITE,
                                         TEE_HANDLE_NULL, &event_marker, sizeof(event_marker), &obj);
    } else if (res == TEE_SUCCESS) {
        TEE_SeekObjectData(obj, 0, TEE_DATA_SEEK_END);
        TEE_WriteObjectData(obj, &event_marker, sizeof(event_marker));
    }
    if (res == TEE_SUCCESS) {
        TEE_CloseObject(obj);
        IMSG("SUCCESS: Tamper event appended to Secure Journal.");
    }
}

/* ── Helper: Check Secure Storage on Startup ───────────────────────────────── */
static void check_persistent_tamper(void) {
    if (get_log_count() > 0) {
        IMSG("!!! WARNING: Persistent Tamper Logs Found. System Locked !!!");
        keys_active = false;
    } else {
        IMSG("Startup Check: Secure Journal is clean.");
    }
}

/* ── Helper: Zeroize the HSM ───────────────────────────────────────────────── */
static void zeroize_hsm(void) {
    if (!keys_active) return;
    IMSG("!!! TAMPER RESPONSE: ZEROIZING ALL CRYPTO KEYS !!!");
    keys_active = false;
    append_tamper_log();
}

// ── NEW: Handle I2C tamper event from host ─────────────────────────────────
// params[0].value.a = severity (I2C_SEVERITY_WARNING or I2C_SEVERITY_CRITICAL)
// params[0].value.b = raw byte received from ESP32 (for logging/debug)
static TEE_Result handle_i2c_tamper(uint32_t param_types, TEE_Param params[4]) {
    if (param_types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
                                       TEE_PARAM_TYPE_NONE,
                                       TEE_PARAM_TYPE_NONE,
                                       TEE_PARAM_TYPE_NONE)) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    uint32_t severity  = params[0].value.a;
    uint32_t raw_byte  = params[0].value.b;

    EMSG("[I2C TAMPER] Severity=%u  RawByte=0x%02X", severity, raw_byte);
    append_tamper_log();

    switch (severity) {
    case I2C_SEVERITY_WARNING:
        // Treat like a voltage/temp anomaly — raise suspicion but don't
        // immediately zeroize; let the threshold logic decide.
        suspicion_score += 30;
        EMSG("[I2C TAMPER] WARNING — suspicion_score now %d", suspicion_score);
        if (suspicion_score > 50 && keys_active) {
            EMSG("[I2C TAMPER] Threshold exceeded after WARNING. Zeroizing.");
            zeroize_hsm();
        }
        break;

    case I2C_SEVERITY_CRITICAL:
        // Immediate, unconditional zeroize — same as enclosure breach.
        EMSG("[I2C TAMPER] CRITICAL — Immediate zeroize.");
        zeroize_hsm();
        break;

    default:
        // Unknown severity — treat conservatively as critical.
        EMSG("[I2C TAMPER] Unknown severity %u — defaulting to CRITICAL.", severity);
        zeroize_hsm();
        break;
    }

    return TEE_SUCCESS;
}
// ─────────────────────────────────────────────────────────────────────────────

/* Mandatory TA entry points */
TEE_Result TA_CreateEntryPoint(void) {
    IMSG("HSM TA Created. Running Startup Security Checks...");
    check_persistent_tamper();
    return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void) {
    IMSG("HSM Tamper TA Destroyed");
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types,
        TEE_Param params[4], void **sess_ctx) {
    (void)&param_types; (void)&params; (void)&sess_ctx;
    IMSG("HSM Tamper Session Opened");
    return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void *sess_ctx) {
    (void)&sess_ctx;
    IMSG("HSM Tamper Session Closed");
}

/* Mandatory: Main command dispatcher */
TEE_Result TA_InvokeCommandEntryPoint(void *sess_ctx, uint32_t cmd_id,
            uint32_t param_types, TEE_Param params[4]) {

    (void)&sess_ctx;
    TEE_Time current_time;
    TEE_GetSystemTime(&current_time);

    // Silence / starvation check on every command
    if (last_heartbeat.seconds != 0) {
        uint32_t silence_ms = (current_time.seconds - last_heartbeat.seconds) * 1000 +
                              (current_time.millis  - last_heartbeat.millis);
        if (silence_ms > SILENCE_THRESHOLD_MS) {
            EMSG("CRITICAL: Silence Detected (%u ms)! Possible Denial of Service.", silence_ms);
            suspicion_score += 10;
            append_tamper_log();
            if (suspicion_score > 50 && keys_active) {
                zeroize_hsm();
                DMSG("Keys Zeroized due to Silence");
            }
        }
    }

    switch (cmd_id) {
    case CMD_HEARTBEAT:
        if (last_heartbeat.seconds != 0) {
            uint32_t diff_ms = (current_time.seconds - last_heartbeat.seconds) * 1000 +
                               (current_time.millis  - last_heartbeat.millis);
            if (diff_ms > 3000) {
                suspicion_score += 5;
                append_tamper_log();
                EMSG("WARNING: Heartbeat Jitter Detected! diff=%u ms  score=%d",
                     diff_ms, suspicion_score);
            } else if (suspicion_score > 0) {
                suspicion_score--;
            }
            if (suspicion_score > 100 && keys_active) {
                EMSG("CRITICAL TAMPER: Threshold reached. Auto-Zeroizing.");
                zeroize_hsm();
            }
        }
        if (!keys_active) return TEE_ERROR_ACCESS_DENIED;
        last_heartbeat = current_time;
        return TEE_SUCCESS;

    case CMD_ZEROIZE_KEYS:
        zeroize_hsm();
        return TEE_SUCCESS;

    case CMD_GET_LOG_COUNT: {
        uint32_t diff_ms = (current_time.seconds - last_heartbeat.seconds) * 1000 +
                           (current_time.millis  - last_heartbeat.millis);
        if (param_types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_OUTPUT,
                                           TEE_PARAM_TYPE_NONE,
                                           TEE_PARAM_TYPE_NONE,
                                           TEE_PARAM_TYPE_NONE)) {
            return TEE_ERROR_BAD_PARAMETERS;
        }
        params[0].value.a = get_log_count();
        params[0].value.b = suspicion_score;
        IMSG("Tamper Events: %u  diff_ms=%u", params[0].value.a, diff_ms);
        return TEE_SUCCESS;
    }

    case CMD_VOLTAGE_ANOMALY:
        append_tamper_log();
        suspicion_score += 30;
        if (suspicion_score > 50) zeroize_hsm();
        return TEE_SUCCESS;

    case CMD_TEMP_ANOMALY:
        append_tamper_log();
        suspicion_score += 25;
        if (suspicion_score > 50) zeroize_hsm();
        return TEE_SUCCESS;

    case CMD_ENCLOSURE_BREACH:
        EMSG("PHYSICAL TAMPER: Enclosure opened!");
        append_tamper_log();
        zeroize_hsm();
        return TEE_SUCCESS;

    case CMD_RESET_TAMPER: {
        IMSG("ADMIN RESET: Clearing tamper journal and re-arming keys.");
        TEE_ObjectHandle obj;
        TEE_Result del_res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE,
                                                       TAMPER_JOURNAL, strlen(TAMPER_JOURNAL),
                                                       TEE_DATA_FLAG_ACCESS_WRITE_META, &obj);
        if (del_res == TEE_SUCCESS) {
            TEE_CloseAndDeletePersistentObject1(obj);
            IMSG("Tamper journal deleted.");
        } else {
            IMSG("No tamper journal found (already clean).");
        }
        keys_active     = true;
        suspicion_score = 0;
        IMSG("System re-armed. keys_active=true, suspicion_score=0");
        return TEE_SUCCESS;
    }

    // ── NEW ──────────────────────────────────────────────────────────────────
    case CMD_I2C_TAMPER:
        return handle_i2c_tamper(param_types, params);
    // ─────────────────────────────────────────────────────────────────────────

    default:
        return TEE_ERROR_BAD_PARAMETERS;
    }
}