#ifndef BATTERYSTATUS_H
#define BATTERYSTATUS_H

    #include <stdint.h>

    #define MAX_BATTERY_VOLTAGE 2.07
    #define MIN_BATTERY_VOLTAGE 1.48


    float Battery_Voltage(void);
    void adc_Init(void);
    int CalculateBatteryPercentage(float);


#endif



