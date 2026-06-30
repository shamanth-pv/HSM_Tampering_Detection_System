#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <tee_client_api.h>
#include "hsm_tamper.h"
#include <fcntl.h>
#include <sys/ioctl.h>
#include <linux/i2c-dev.h>
#include <linux/i2c.h>
#include <stdint.h>

#define I2C_BUS         "/dev/i2c-1"   // Change to match your bus
#define ESP32_ADDR      0x08
#define I2C_READ_LEN    32

// I2C tamper severity levels (must match TA defines)
#define I2C_SEVERITY_WARNING    1
#define I2C_SEVERITY_CRITICAL   2

// Global flag to prevent threads from calling the TA before it's ready
volatile int tee_ready = 0;

int sock = -1;
TEEC_Session sess;
int is_compromised = 0;
int is_connected = 0;

// ─────────────────────────────────────────────
// I2C Listener Thread
// ─────────────────────────────────────────────
void *i2c_listener(void *arg) {
    int fd = -1;
    uint8_t buf[I2C_READ_LEN];
    uint8_t prev_data[I2C_READ_LEN];
    int     prev_len      = 0;
    int     has_prev_data  = 0;

    while (1) {
        // (Re)open the bus if not already open
        if (fd < 0) {
            fd = open(I2C_BUS, O_RDWR);
            if (fd < 0) {
                perror("[I2C] Failed to open bus, retrying...");
                sleep(2);
                continue;
            }

            // Set the slave address
            if (ioctl(fd, I2C_SLAVE, ESP32_ADDR) < 0) {
                perror("[I2C] Failed to set slave address");
                close(fd);
                fd = -1;
                sleep(2);
                continue;
            }

            printf("[I2C] Bus open, listening to ESP32 @ 0x%02X\n", ESP32_ADDR);
        }

        memset(buf, 0, sizeof(buf));
        int n = read(fd, buf, I2C_READ_LEN);

        if (n < 0) {
            // ESP32 not ready / NACK — back off silently
            usleep(200000);
            continue;
        }

        if (n > 0 && tee_ready) {
            printf("[I2C] Received %d byte(s): ", n);
            for (int i = 0; i < n; i++) printf("%02X ", buf[i]);
            printf("\n");

            if (!has_prev_data) {
                // First successful read — store as baseline
                memcpy(prev_data, buf, n);
                prev_len      = n;
                has_prev_data = 1;
                printf("[I2C] Baseline data stored (%d bytes).\n", n);
            } else {
                // Compare with previous data
                int data_changed = (n != prev_len) ||
                                   (memcmp(buf, prev_data, n) != 0);

                if (data_changed) {
                    printf("[I2C] DATA CHANGE DETECTED — TAMPER!\n");
                    printf("[I2C]   Previous (%d bytes): ", prev_len);
                    for (int i = 0; i < prev_len; i++) printf("%02X ", prev_data[i]);
                    printf("\n");
                    printf("[I2C]   Current  (%d bytes): ", n);
                    for (int i = 0; i < n; i++) printf("%02X ", buf[i]);
                    printf("\n");

                    // Invoke TA with CRITICAL severity to zeroize keys
                    printf("[I2C] Invoking TEE CMD_I2C_TAMPER (CRITICAL — data changed)\n");

                    TEEC_Operation op = {0};
                    op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
                                                     TEEC_NONE,
                                                     TEEC_NONE,
                                                     TEEC_NONE);
                    op.params[0].value.a = I2C_SEVERITY_CRITICAL;
                    op.params[0].value.b = buf[0];  // First byte for forensic log

                    TEEC_Result res = TEEC_InvokeCommand(&sess, CMD_I2C_TAMPER, &op, NULL);

                    if (res == TEEC_SUCCESS) {
                        printf("[I2C] TEE acknowledged tamper — keys zeroized.\n");
                    } else {
                        printf("[I2C] TEE returned error: 0x%08X\n", res);
                    }

                    is_compromised = 1;

                    // Update stored data to the new values
                    memcpy(prev_data, buf, n);
                    prev_len = n;
                }
            }
        }

        usleep(100000); // Poll at ~10 Hz
    }

    close(fd);
    return NULL;
}

// ─────────────────────────────────────────────
// Network Listener Thread
// ─────────────────────────────────────────────
void *network_listener(void *arg) {
    char buffer[1024];
    while (1) {
        if (is_connected && sock != -1) {
            int valread = read(sock, buffer, 1024);
            if (valread <= 0) {
                printf("[Host] Connection lost. Waiting for reconnect...\n");
                is_connected = 0;
                close(sock);
                sock = -1;
            } else if (strncmp(buffer, "ZEROIZE", 7) == 0) {
                printf("[Host] ALERT: REMOTE ZEROIZE RECEIVED!\n");
                TEEC_Operation op = {0};
                TEEC_InvokeCommand(&sess, CMD_ZEROIZE_KEYS, &op, NULL);
                is_compromised = 1;
            }
        }
        usleep(100000);
    }
    return NULL;
}

// ─────────────────────────────────────────────
// Heartbeat Sender Thread
// ─────────────────────────────────────────────
void *heartbeat_sender(void *arg) {
    while (1) {
        if (!tee_ready) {
            usleep(100000);
            continue;
        }

        // 1. Ping the Secure World
        TEEC_Operation op = {0};
        TEEC_InvokeCommand(&sess, CMD_HEARTBEAT, &op, NULL);

        // 2. Fetch current log count and suspicion score from Secure Storage
        uint32_t logs = 0;
        uint32_t suspicion_score = 0;

        op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_OUTPUT,
                                         TEEC_NONE,
                                         TEEC_NONE,
                                         TEEC_NONE);

        TEEC_Result res = TEEC_InvokeCommand(&sess, CMD_GET_LOG_COUNT, &op, NULL);

        if (res == TEEC_SUCCESS) {
            logs            = op.params[0].value.a;
            suspicion_score = op.params[0].value.b;
        }

        // 3. Send telemetry to dashboard if connected
        // Also surfaces i2c_compromised flag in the JSON for dashboard visibility
        if (is_connected && sock != -1) {
            char json_packet[256];
            sprintf(json_packet,
                    "{\"status\": \"%s\", \"jitter\": 10, \"tamper_logs\": %u, \"i2c_compromised\": %s}",
                    ((logs > 0) && suspicion_score > 100) ? "COMPROMISED" : "ALIVE",
                    logs,
                    is_compromised ? "true" : "false");

            if (send(sock, json_packet, strlen(json_packet), MSG_DONTWAIT) < 0) {
                is_connected = 0;
            }
        }

        usleep(200000); // 5 Hz — faster so timing diff is visible on RPi3
    }
    return NULL;
}

// ─────────────────────────────────────────────
// Main
// ─────────────────────────────────────────────
int main(void) {
    TEEC_Context ctx;
    TEEC_UUID    uuid = TA_HSM_TAMPER_UUID;
    pthread_t    send_id, listen_id, i2c_id;

    // 1. Initialize Secure World session
    TEEC_InitializeContext(NULL, &ctx);
    TEEC_Result res = TEEC_OpenSession(&ctx, &sess, &uuid,
                                       TEEC_LOGIN_PUBLIC, NULL, NULL, NULL);
    if (res != TEEC_SUCCESS) {
        printf("[Host] Failed to open TEE session: 0x%08X\n", res);
        return -1;
    }

    printf("[Host] TEE session opened successfully.\n");

    // 1b. Reset any previous tamper state so the system starts clean
    {
        TEEC_Operation op = {0};
        op.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_NONE, TEEC_NONE, TEEC_NONE);
        TEEC_Result reset_res = TEEC_InvokeCommand(&sess, CMD_RESET_TAMPER, &op, NULL);
        if (reset_res == TEEC_SUCCESS) {
            printf("[Host] Admin reset successful — system re-armed.\n");
            is_compromised = 0;
        } else {
            printf("[Host] Admin reset returned: 0x%08X\n", reset_res);
        }
    }

    tee_ready = 1;

    // 2. Start all threads
    pthread_create(&send_id,   NULL, heartbeat_sender,  NULL);
    pthread_create(&listen_id, NULL, network_listener,  NULL);
    pthread_create(&i2c_id,    NULL, i2c_listener,      NULL);

    // 3. Resilient network connection loop
    struct sockaddr_in serv_addr;
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port   = htons(5555);
    inet_pton(AF_INET, "10.0.2.2", &serv_addr.sin_addr);

    while (1) {
        if (!is_connected) {
            sock = socket(AF_INET, SOCK_STREAM, 0);
            if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) == 0) {
                printf("[Host] Connected to Dashboard.\n");
                is_connected = 1;
            } else {
                close(sock);
                sock = -1;
                // Quietly retry
            }
        }
        sleep(2);
    }

    return 0; // Never reached
}
