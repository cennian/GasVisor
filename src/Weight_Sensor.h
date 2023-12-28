#ifndef WEIGHT_SENSOR_H
#define WEIGHT_SENSOR_H

#include <sensor/hx711/hx711.h>
#include <zephyr/logging/log.h>

void calibrate_sensor(void);
void measure_weight(void);


#endif