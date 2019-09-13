#!/bin/bash

mkdir -p coverage

# Make sure android is up and running
while [ "`adb shell getprop init.svc.bootanim`" != "stopped" ]; do sleep 10; done

# Travis is SLOWWW
if [ ! -z $TRAVIS ]; then
    echo "In Travis... Sleeping 5 minutes to let emulator boot."
    sleep 300
fi

pytest -v --cov --cov-report=term --cov-report=html $@ tests/android/
