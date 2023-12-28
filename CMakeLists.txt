#
# Copyright (c) 2020 Nordic Semiconductor
#
# SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
#

cmake_minimum_required(VERSION 3.20.0)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(Gasvisorfirmware)

# NORDIC SDK APP START
target_sources(app PRIVATE src/main.c)
target_sources(app PRIVATE src/BatteryStatus.c)
target_sources(app PRIVATE src/SleepMode.c)
target_sources(app PRIVATE src/Weight_Sensor.c)
target_sources(app PRIVATE src/IoTConnectSDK.c)

# NORDIC SDK APP END

