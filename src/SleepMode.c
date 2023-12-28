#include "SleepMode.h"


LOG_MODULE_REGISTER(SLEEPMDOE);


unsigned long sleepTime  =  5 *  60 * 1000UL;
const struct device *const cons = DEVICE_DT_GET(DT_CHOSEN(zephyr_console));

	
   


/*********************************************************************
 * @fn      		  - sleepmode
 *
 * @brief             This function puts the device into a sleep mode.
 *
 * @param[in]         None.
 *
 * @return            None.
 *
 * @Note              This function checks if the device is ready,
 *                    suspends it, sleeps for the specified time, and then
 *                    resumes the device. Sleep Time can be changed from sleepTime.
 */
void sleepmode()
{
        if(!device_is_ready(cons))
    {
		 LOG_ERR("%s: device not ready.\n", cons->name);
		return 0;
	}
		pm_device_action_run(cons, PM_DEVICE_ACTION_SUSPEND);
		k_msleep(sleepTime);
		pm_device_action_run(cons, PM_DEVICE_ACTION_RESUME);
}