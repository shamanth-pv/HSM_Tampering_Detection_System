#ifndef SENSOR_HAL_H
#include <stdint.h>
#define SENSOR_HAL_H
typedef enum {
    SENSOR_VOLTAGE = 0,
    SENSOR_ENCLOSURE,
    SENSOR_TEMPERATURE,
    SENSOR_MESH_ACTIVE,
    SENSOR_PUF
} sensor_id_t;

typedef struct {
    int32_t voltage_mv;
    int32_t temperature_c;
    int32_t enclosure_state;
    uint8_t mesh_response;
    uint64_t puf_challenge;
} sensor_data_t;

int hal_read_sensor(sensor_id_t id, sensor_data_t *data);
void hal_zeroize_level4(void);
#endif
