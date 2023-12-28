#include "BatteryStatus.h"

#include <inttypes.h>
#include <stddef.h>


#include <zephyr/device.h>
#include <zephyr/logging/log.h>
#include <zephyr/devicetree.h>
#include <zephyr/drivers/adc.h>
#include <zephyr/kernel.h>
#include <zephyr/sys/printk.h>
#include <zephyr/sys/util.h>
 LOG_MODULE_REGISTER(BATTERY);


// // Global variables
int err;
uint16_t buf;
int32_t val_mv;
float voltage_mapped;





#if !DT_NODE_EXISTS(DT_PATH(zephyr_user)) || \
    !DT_NODE_HAS_PROP(DT_PATH(zephyr_user), io_channels)
#error "No suitable devicetree overlay specified"
#endif

#define DT_SPEC_AND_COMMA(node_id, prop, idx) \
    ADC_DT_SPEC_GET_BY_IDX(node_id, idx),

/* Data of ADC io-channels specified in devicetree. */
static const struct adc_dt_spec adc_channels[] = {
    DT_FOREACH_PROP_ELEM(DT_PATH(zephyr_user), io_channels,
                         DT_SPEC_AND_COMMA)
};

struct adc_sequence sequence = {
    .buffer = &buf,
    /* buffer size in bytes, not number of samples */
    .buffer_size = sizeof(buf),
};

/*********************************************************************
 * @fn                - Battery_Voltage
 *
 * @brief             - Reads the battery voltage via ADC, converts it to millivolts, 
 *                      and then maps it to the corresponding voltage value (according to Voltage Divider).
 *
 * @return            - The mapped voltage value as a float.
 *
 * @Note              - This function is used for Voltage Divider ( R1 = 100, R2 = 100).
 */
float Battery_Voltage(void) {
    (void)adc_sequence_init_dt(&adc_channels[0], &sequence);
    err = adc_read(adc_channels[0].dev, &sequence);
    if (err < 0) {
        LOG_WRN("Could not read (%d)", err);
        return;
    }

    val_mv = (int16_t)buf;
    LOG_INF("Analog Value: %" PRId32, val_mv);
    err = adc_raw_to_millivolts_dt(&adc_channels[0], &val_mv);
    if (err < 0) {
        LOG_INF(" (value in mV not available)");
    } else {
        //LOG_INF(" Milli_Voltage: = %" PRId32 " mV", val_mv);
    }

    float voltage = (float)val_mv / 1000.0; // Convert millivolts to volts
    voltage_mapped = 2 * voltage;
   

    return voltage_mapped;

    
}

/*********************************************************************
 * @fn                - adc_Init
 *
 * @brief             - Initializes the ADC for battery voltage reading.
 *
 * @return            - void
 *
 * @Note              - This function checks if the ADC device is ready and sets up 
 *                      the ADC channel for reading the battery voltage.
 */
void adc_Init(void) {
    if (!adc_is_ready_dt(&adc_channels[0])) {
        LOG_ERR("ADC controller device %s not ready", adc_channels[0].dev->name);
        return;
    }

    err = adc_channel_setup_dt(&adc_channels[0]);
    if (err < 0) {
        LOG_ERR("Could not setup channel #%d (%d)", 0, err);
        return;
    }
}

/*********************************************************************
 * @fn                - CalculateBatteryPercentage
 *
 * @brief             - Calculates the battery percentage based on the averaged voltage.
 *
 * @param[in]         - averagedVoltage: Average of Voltage from Battery_Voltage function.
 *
 * @return            - The calculated battery percentage as an integer.
 *
 * @Note              - This function computes the battery percentage by mapping the 
 *                      averaged voltage between a defined minimum and maximum voltage.
 */
int CalculateBatteryPercentage(float averagedVoltage) {
    int battery_percentage = (averagedVoltage - MIN_BATTERY_VOLTAGE) / (MAX_BATTERY_VOLTAGE - MIN_BATTERY_VOLTAGE) * 100;

    // Clamp the percentage to the range [0, 100]
    if (battery_percentage > 100) {
        battery_percentage = 100;
    } else if (battery_percentage < 0) {
        battery_percentage = 0;
    }

    return battery_percentage;
}