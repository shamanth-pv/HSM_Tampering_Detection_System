#ifndef TAMPER_CORE_H
#include "../hal/sensor_hal.h"
#include <stdint.h>
#define TAMPER_CORE_H
typedef enum {
    TAMPER_NONE = 0,
    TAMPER_VOLTAGE_GLITCH,
    TAMPER_ENCLOSURE_OPEN,
    TAMPER_TEMP_SPIKE,
    TAMPER_MESH_ATTACK,
    TAMPER_PUF_FAIL
} tamper_type_t;

typedef struct {
    tamper_type_t type;
    uint32_t event_id;
    char hash[65];
} tamper_event_t;

tamper_event_t check_tamper_level4(sensor_data_t *sensors);
#endif
