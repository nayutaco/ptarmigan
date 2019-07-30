#!/bin/bash
set -eu

START=`date +%s`

source ../../install/jdk.sh
./testj_prepare.sh
./test_after.sh BITCOINJ

if [ $# -eq 1 ] && [ $1 = "stop" ]; then
    exit 0
fi

echo clean start
./clean.sh
echo clean end

END=`date +%s`
ELAPSED=`expr $END - $START` 
echo "$ELAPSED seconds"
