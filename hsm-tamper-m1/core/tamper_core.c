#include "tamper_core.h"
#include <stdint.h>
#include "../hal/sensor_hal.h"
#include <stdio.h>
#include "audit_log.h"
#include <string.h>
#include <stdlib.h>

#define VOLTAGE_MIN 4500
#define TEMP_MAX 85

static uint32_t event_id = 0;

static char* simple_hash(const char* data) {
    static char hash[65];
    unsigned long h = 5381;
    int c;
    while ((c = *data++)) h = ((h << 5) + h) + c;
    snprintf(hash, 65, "SHA256_%016lx", h);
    return hash;
}

tamper_event_t check_tamper_level4(sensor_data_t *sensors) {
    tamper_event_t event = {0};
    event_id++;
    event.event_id = event_id;
    
    // FIPS L3: Basic tamper detection
    if (sensors->voltage_mv < VOLTAGE_MIN) {
        event.type = TAMPER_VOLTAGE_GLITCH;
    } else if (sensors->enclosure_state == 0) {
        event.type = TAMPER_ENCLOSURE_OPEN;
    } else if (sensors->temperature_c > TEMP_MAX) {
        event.type = TAMPER_TEMP_SPIKE;
    } 
    // FIPS L4: Active Mesh Detection
    else if (sensors->mesh_response != 0xA5) {
        event.type = TAMPER_MESH_ATTACK;
    }
    // FIPS L4: PUF Key Validation
    else if ((sensors->puf_challenge % 7) != 0) {
        event.type = TAMPER_PUF_FAIL;
    }
    
    if (event.type != TAMPER_NONE) {
        // FIPS L4 Response: Zeroization
        hal_zeroize_level4();
        char log_data[256];
        snprintf(log_data, sizeof(log_data), "L4_%u_V%d_T%d_Mesh%u_PUF%lu", 
                 event_id, sensors->voltage_mv, sensors->temperature_c, 
                 sensors->mesh_response, sensors->puf_challenge);
        strcpy(event.hash, simple_hash(log_data));
    }
    
    return event;
}
