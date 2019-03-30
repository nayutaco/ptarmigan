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
while :
do
    GI3=`./ptarmcli -l 3334 | grep 'node_id' | wc -l`
    GI4=`./ptarmcli -l 4445 | grep 'node_id' | wc -l`
    if [ ${GI3} -gt 0 ] && [ ${GI4} -gt 0 ]; then
        break
    fi
    sleep 2
done