#!/bin/bash

mkdir -p coverage

pytest -v --cov --cov-report=term --cov-report=html tests/android/
