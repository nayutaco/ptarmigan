#!/bin/sh

killall ptarmd
for i in 3333 4444
do
    ./ptarmd -d ./node_$i -c ../regtest.conf --network=regtest &
done

sleep 1

# ノード接続
#
./ptarmcli -c conf/peer4444.conf 3334
