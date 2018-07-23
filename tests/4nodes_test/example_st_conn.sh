#!/bin/sh

killall ptarmd
for i in 3333 4444 5555 6666
do
    ./ptarmd -d ./node_$i -c ../regtest.conf &
done

sleep 1

# ノード接続
#
./ptarmcli -c conf/peer4444.conf 3334
./ptarmcli -c conf/peer5555.conf 3334
./ptarmcli -c conf/peer5555.conf 6667
