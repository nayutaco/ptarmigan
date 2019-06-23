#!/bin/bash
set -eu

if [ ! -f ./test_after_uni$1.sh ]; then
    echo unknown test pattern
    exit 1
fi

START=`date +%s`

./testd_prepare.sh
./test_after_uni$1.sh BITCOIND

echo ---------------- test$1 end ----------------

bitcoin-cli -datadir=. -conf=regtest.conf listunspent | jq -e '. | map(select(.amount < 1))'
# bitcoin-cli -datadir=. -conf=regtest.conf listtransactions | jq -e '.| map(select(.category == "receive"))'

if [ $# -eq 2 ] && [ $2 = "stop" ]; then
    exit 0
fi

echo clean start
./clean.sh
echo clean end

END=`date +%s`
ELAPSED=`expr $END - $START` 
echo "$ELAPSED seconds"
