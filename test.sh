#!/bin/bash

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
pushd . >/dev/null
cd $DIR
mkdir -p coverage

./test_linux.sh
./test_android.sh

popd >/dev/null
