#!/bin/bash

mkdir -p coverage

# Make sure android is up and running
while [ "`adb shell getprop init.svc.bootanim`" != "stopped" ]; do sleep 10; done

# Current issues with latest frida server release...
# android = device_types.AndroidDevice(type='usb', frida_server_release='12.6.11') <-- use this for testing manuall
pytest -v --cov --cov-report=term --cov-report=html $@ tests/android/
