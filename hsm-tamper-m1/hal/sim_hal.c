#include "sensor_hal.h"
#include <stdint.h>
#include <stdlib.h>
#include <time.h>

static int scenario = 0;

int hal_read_sensor(sensor_id_t id, sensor_data_t *data) {
    srand(time(NULL) + scenario);
    switch(id) {
        case SENSOR_VOLTAGE:
            data->voltage_mv = (scenario == 1) ? 3800 : 5000 + (rand() % 400 - 200);
            break;
        case SENSOR_ENCLOSURE:
            data->enclosure_state = (scenario == 2) ? 0 : 1;
            break;
        case SENSOR_TEMPERATURE:
            data->temperature_c = (scenario == 3) ? 95 : 50 + (rand() % 20 - 10);
            break;
        case SENSOR_MESH_ACTIVE:
            data->mesh_response = (scenario == 4) ? 0xFF : 0xA5;
            break;
        case SENSOR_PUF:
            data->puf_challenge = (scenario == 5) ? 1 : rand();
            break;
    }
    return 0;
}
void hal_zeroize_level4(void) {}
