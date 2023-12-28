 #include "Weight_Sensor.h"

// Register the module for logging purposes
 LOG_MODULE_REGISTER(WEIGHT);

 const struct device *hx711_dev; /* This device will be used for the measurement of load cell*/

 int reference_weight_grams = 2000;  /* Calibrated for 2000 grams, needs more fine-tuning*/
 int calibration_iterations = 2;

 int16_t weight_grams;              // Variable to store the measured weight in grams


/*********************************************************************
 * @fn      		  - hx711_init
 *
 * @brief             Initializes the HX711 sensor device.
 *
 * @param[in]         None.
 *
 * @return            None.
 *
 * @Note              This function initializes the HX711 sensor device
 *                    and logs its name.
 */
 void hx711_init()
 {
      // Initialize the HX711 sensor
     hx711_dev = DEVICE_DT_GET_ANY(avia_hx711);
     __ASSERT(hx711_dev == NULL, "Failed to get device binding\n");

    LOG_INF("Device is %p, name is %s", hx711_dev, hx711_dev->name);

 }

/*********************************************************************
 * @fn      		  - calibrate_sensor
 *
 * @brief             Calibrates the HX711 load cell sensor.
 *
 * @param[in]         None.
 *
 * @return            None.
 *
 * @Note              This function performs sensor tare, wait for some time, and then
 *                    calibrates the sensor using the reference weight.
 */
 void calibrate_sensor(void) {

     avia_hx711_tare(hx711_dev, calibration_iterations);

     // Wait for the user to place the reference weight on the sensor


 	LOG_INF("Calibrating load cells----\n");
    for (int i = calibration_iterations; i >= 0; i--) {
        LOG_INF(" %d..", i);
        k_msleep(250);
    }

//     // Calibrate the sensor using the reference weight
     avia_hx711_calibrate(hx711_dev, reference_weight_grams, calibration_iterations);

     LOG_INF("Calibration complete.\n");
 }


/*********************************************************************
 * @fn      		  - measure_weight
 *
 * @brief             - Measures the weight using the HX711 sensor.
 *
 * @param[in]         - None.
 *
 * @return            - None.
 *
 * @Note              - This function fetches and measures the weight using
 *                      the HX711 sensor and logs the measured weight in grams.
 */
void measure_weight(void) {
    static struct sensor_value weight;
    int ret;

    ret = sensor_sample_fetch(hx711_dev);
    if (ret != 0) {
        LOG_ERR("Cannot take measurement: %d", ret);
    } else {
        sensor_channel_get(hx711_dev, HX711_SENSOR_CHAN_WEIGHT, &weight);
        LOG_INF("Weight: %d.%06d grams", weight.val1, weight.val2);
    }
	 weight_grams = weight.val1 + weight.val2;
     if(weight_grams <0){
        weight_grams =0;
     }
     else if(weight_grams>32767){
        weight_grams = 32000;
     }

}