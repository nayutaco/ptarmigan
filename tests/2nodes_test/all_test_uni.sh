#!/bin/bash
set -eu

if [ ! -f ./test_after_uni$1.sh ]; then
    echo unknown test pattern
    exit 1
fi

START=`date +%s`

./testd_prepare.sh
./test_after_uni$1.sh BITCOIND

if [ $# -eq 1 ] && [ $1 == "stop" ]; then
    exit 0
fi

echo clean start
./clean.sh
echo clean end

END=`date +%s`
ELAPSED=`expr $END - $START` 
echo "$ELAPSED seconds"
