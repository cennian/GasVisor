# Firmware-IoT-Connect-MQTT

VisualStudioCode 1.83.1

SDK Nordic 2.5.0

DevoMech code V1.2





28/12/2023

Separate header files for Sleep Mode, Battery Status, Weight Sensors.
Cleaned the code.
Callibration will be Done only once when device starts.
uint16_t value is used for sending weight to IoT Connect server.
float is converted to string for sending battery data to IoT connect server,
Because Float cant be truncated to decimal points and causes issues.

(Added Battery State Switch Pin to turn on ADC on PCB.)
System goes to sleep mode for 5 minute, Wakeups and takes weight measurement, Measures Voltage, takes average and calculates Battery Percentage, initializes LTE, connects to IoTConnect, publishes data, disconnects, and goes to sleep again.

Template used : "Device4" (type = token) (Attributes : "Weight", "BatteryStatus")
 Avnet Credentials:
 #define IOTCONNECT_DEVICE_UNIQUE_ID    "DevoDevice4"
 #define IOTCONNECT_DEVICE_CP_ID        "75931fa19a194a7aa64d2565a942051d"
 #define IOTCONNECT_DEVICE_ENV          "emea"

 Note:  Program throws 49 warnings. Warnings are mostly from SDK (IoT Connect portal).
        Only few warnings are from "pm" and "hx711" header files.
        6 Warnings from Problem section ( from prj.config file).
        *Warnings and problems will be taken care of in future*