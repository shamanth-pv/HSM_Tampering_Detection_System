#include "../hal/sensor_hal.h"
#include "../core/tamper_core.h"
#include "../monitor/siem.h"
#include "../core/audit_log.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

const char* tamper_names[] = {"NONE", "VOLTAGE_GLITCH", "ENCLOSURE_OPEN", "TEMP_SPIKE", "MESH_ATTACK", "PUF_FAIL"};

int main() {
    printf("=== Production HSM FIPS L4 + SIEM + Audit Log ===\n");
    
    sensor_data_t sensors = {0};
    const char* scenarios[] = {"NORMAL", "VOLTAGE_GLITCH", "ENCLOSURE_OPEN", "TEMP_SPIKE", "MESH_ATTACK", "PUF_FAIL"};
    
    for (int i = 0; i < 6; i++) {
        hal_read_sensor(SENSOR_VOLTAGE, &sensors);
        hal_read_sensor(SENSOR_ENCLOSURE, &sensors);
        hal_read_sensor(SENSOR_TEMPERATURE, &sensors);
        hal_read_sensor(SENSOR_MESH_ACTIVE, &sensors);
        hal_read_sensor(SENSOR_PUF, &sensors);
        
        switch(i) {
            case 1: sensors.voltage_mv = 3800; break;
            case 2: sensors.enclosure_state = 0; break;
            case 3: sensors.temperature_c = 95; break;
            case 4: sensors.mesh_response = 0xFF; break;
            case 5: sensors.puf_challenge = 1; break;
        }
        
        tamper_event_t event = check_tamper_level4(&sensors);
        
        printf("[%s] ", scenarios[i]);
        if (event.type == TAMPER_NONE) {
            printf("SECURE ✓\n");
        } else {
            printf("**TAMPER! %s (ID=%u)**\n", tamper_names[event.type], event.event_id);
            siem_alert(tamper_names[event.type], event.hash);           // SIEM alert
            secure_log_event(event.event_id, tamper_names[event.type], event.hash);  // AUDIT LOG
        }
    }
    
    printf("\n[+] Production Features: SIEM + Persistent Audit Log ✓\n");
    printf("Logs saved: logs/audit.jsonl\n");
    return 0;
}
