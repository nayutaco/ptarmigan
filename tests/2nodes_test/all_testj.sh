#!/bin/bash
set -eu

START=`date +%s`

./testj_prepare.sh
./test_after.sh

if [ $# -eq 1 ] && [ $1 == "stop" ]; then
    exit 0
fi

echo clean start
./clean.sh
echo clean end

END=`date +%s`
ELAPSED=`expr $END - $START` 
echo "$ELAPSED seconds"
