#!/bin/sh

# ノードの起動
#
# ここでは連続して起動させているが、動作を見る場合にはコンソールをそれぞれ開き、
# 各コンソールで起動させた方がログを見やすい。
for i in 3333 4444 5555 6666
do
    cp ../testfiles/channel_$i.conf ./node_$i/channel.conf
    ./ptarmd -d ./node_$i -c ../regtest.conf -p $i --network=regtest &
done

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