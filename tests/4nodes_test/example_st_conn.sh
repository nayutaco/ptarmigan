#!/bin/sh

killall ptarmd
for i in 3333 4444 5555 6666
do
    ./ptarmd -d ./node_$i -c ../regtest.conf -p $i --network=regtest >> ptarmd_$i.log &
done

sleep 3

# ノード接続
#
./ptarmcli -c conf/peer4444.conf 3334
./ptarmcli -c conf/peer5555.conf 3334
./ptarmcli -c conf/peer5555.conf 6667

while :
do
    GI3=`./ptarmcli -l 3334 | grep 'node_id' | wc -l`
    GI4=`./ptarmcli -l 4445 | grep 'node_id' | wc -l`
    GI5=`./ptarmcli -l 5556 | grep 'node_id' | wc -l`
    GI6=`./ptarmcli -l 6667 | grep 'node_id' | wc -l`
    if [ ${GI3} -gt 0 ] && [ ${GI4} -gt 0 ] && [ ${GI5} -gt 0 ] && [ ${GI6} -gt 0 ]; then
        break
    fi
    sleep 2
done