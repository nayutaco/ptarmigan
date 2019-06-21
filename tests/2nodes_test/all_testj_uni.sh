#!/bin/bash
set -eu

if [ ! -f ./test_after_uni$1.sh ]; then
    echo unknown test pattern
    exit 1
fi

START=`date +%s`

./testj_prepare.sh
./test_after_uni$1.sh BITCOINJ

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
