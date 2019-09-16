#!/bin/bash
set -eu

if [ $# -eq 0 ]; then
    echo param1=1~4
    exit 1
fi

if [ ! -f ./test_after_uni$1.sh ]; then
    echo unknown test pattern
    exit 1
fi

START=`date +%s`

./testj_prepare.sh
./test_after_uni$1.sh BITCOINJ

echo ---------------- test$1 end ----------------

if [ $# -eq 2 ] && [ $2 = "stop" ]; then
    exit 0
fi

echo clean start
./clean.sh
echo clean end

END=`date +%s`
ELAPSED=`expr $END - $START` 
echo "$ELAPSED seconds"
