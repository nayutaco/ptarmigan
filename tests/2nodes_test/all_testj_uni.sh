#!/bin/bash
set -eu

START=`date +%s`

./testj_prepare.sh
./test_after_uni1.sh

if [ $# -eq 1 ] && [ $1 == "stop" ]; then
    exit 0
fi

exit 0

echo clean start
./clean.sh
echo clean end

END=`date +%s`
ELAPSED=`expr $END - $START` 
echo "$ELAPSED seconds"
