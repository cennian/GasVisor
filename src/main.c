/*
 *  DevoMech code Version 1.2
 *  Integrated with nrf sdk, this sdk does not reliably posts data on the server, it skips data psoting from 10 to 20 %.
 */

#include <string.h>
#include <zephyr/kernel.h>
#include <stdlib.h>
#include <stdint.h>
#include <zephyr/sys/printk.h>
#include <zephyr/sys/util.h>
#include <zephyr/net/socket.h>
#include <modem/nrf_modem_lib.h>
#include <zephyr/net/tls_credentials.h>
#include <modem/pdn.h>
#include <modem/lte_lc.h>
#include <modem/modem_key_mgmt.h>
#include <zephyr/pm/pm.h>
#include <zephyr/pm/device.h>
#include <zephyr/pm/state.h>
#include <zephyr/device.h>
#include <zephyr/logging/log.h>  

#include <zephyr/drivers/adc.h>
#include <zephyr/drivers/gpio.h>
#include <zephyr/settings/settings.h>

// Custom Header Files
#include "BatteryStatus.h"
#include "SleepMode.h"
#include "Weight_Sensor.h"
#include "IoTConnectSDK.h"


LOG_MODULE_REGISTER(MAIN);  
float voltage = 0;               // Voltage of Battery
uint8_t battery_percentage =0;   //Battery Percentage
char battery_data_str[14];       // Character array to store Battery Data.

#define ADC_NODE DT_NODELABEL(adcswitch) // Q1 Transistor pin to turn on ADC
#define ERROR_LED_NODE DT_NODELABEL(errordetectionled) // Error Detection LED (not being used currently in the code)

#define DEFAULT_CALIBRATION_DONE_VALUE 0

static uint8_t calibration_done = DEFAULT_CALIBRATION_DONE_VALUE;

extern const struct device *hx711_dev; /* This device will be used for measurement of load cell*/


/**
 * 	@brief    Sets the calibration settings.
 * 
 * 	@param[1] name The name of the calibration setting to be set. In this context, it checks for "done".
 * 	@param[2] len The length of the data to be read for the calibration setting.
 * 	@param[3] read_cb A callback function to read the calibration data. This function should conform to the `settings_read_cb` type.
 * 	@param[4] cb_arg A pointer to the argument that should be passed to the read_cb callback function.
 * 
 * 
 * 	@return   Returns 0 on successful setting of calibration data.
*/

static int calibration_settings_set(const char *name, size_t len,
                            settings_read_cb read_cb, void *cb_arg)
{
    const char *next;
    int rc;

    if (settings_name_steq(name, "done", &next) && !next) {
        if (len != sizeof(calibration_done)) {
            return -EINVAL;
        }

        rc = read_cb(cb_arg, &calibration_done, sizeof(calibration_done));
        if (rc >= 0) {
            return 0;
        }

        return rc;
    }

    return -ENOENT;
}


struct settings_handler my_conf = {
    .name = "calibration",
    .h_set = calibration_settings_set
};




// ***************************************** Main loop Starts here  ************************************************
/**
 * @brief   - This is the main function where the program execution begins
 * @return  - Returns 0 if the program executes successfully, otherwise returns error code.
 * @param   - None
*/
int main(void)
{
	int err;
	int fd;
	

		/* Calibration Settings Start*/
		settings_subsys_init();
		settings_register(&my_conf);
		settings_load();
		/* Calibration Settings End*/

		static const struct gpio_dt_spec BATTERY_STATE_SWITCH = GPIO_DT_SPEC_GET(ADC_NODE,gpios); // Transistor pin to switch ADC
		gpio_pin_configure_dt(&BATTERY_STATE_SWITCH,GPIO_OUTPUT); // pin used as an OUTPUT

		hx711_init();  // Initialize HX711 for measuring weight
		adc_Init();    // initialize ADC for measuring Battery Voltage

	// ******************************Initialization Done**********************************
	
		
	
			while(1){

				sleepmode();  // You can change the SleepTime in this function
				
					// Wakeup mode //
					LOG_INF("IoT COnnect sample starting\n\r");

					// Callibration will only be done one time. (For Production process)
					if (!calibration_done) {
						calibrate_sensor();
						calibration_done = 1;
						settings_save_one("calibration/done", &calibration_done, sizeof(calibration_done));
					}

					avia_hx711_power(hx711_dev,HX711_POWER_ON);  // Turn on Hx711

				
					for(int i = 0; i<3; i++) {
						k_msleep(450); 
						measure_weight();
						}

					avia_hx711_power(hx711_dev,HX711_POWER_OFF);  // Turn off Hx711

				
					voltage = 0;
					battery_percentage = 0;
				
					gpio_pin_set_dt(&BATTERY_STATE_SWITCH,1);  // Turned on Transistor (Q1)
					k_msleep(450);
					for(int i=0; i<3; i++){

						voltage += Battery_Voltage();  
						k_msleep(450);
					}
					gpio_pin_set_dt(&BATTERY_STATE_SWITCH,0); // Turned off Transistor (Q1)
					voltage = voltage/3; 				//Averaging the readings
					
					battery_percentage = CalculateBatteryPercentage(voltage);  // Calculates Battery Percentage
					printf("average_voltage: %.2f\n\r",voltage); 			   // float doesnt work on LOGS, so printf is used.
					LOG_INF("Battery: %d %%", (int)battery_percentage);
					
					snprintf(battery_data_str, sizeof(battery_data_str), "%.2f V, %d%%", voltage, battery_percentage);
    				LOG_INF("Battery Data: %s", battery_data_str);
				

					//publish data
					
					IoT_Connect_main();  // Connects to IoT connect and publishes data. (This function is under working by Avnet Team)
					lte_lc_power_off();  // Turns off LTE Modem
				
				}	
}
//****************************************************** main loop ends here ***************************************************************






