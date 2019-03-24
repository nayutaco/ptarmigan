#!/bin/sh
#
#
#  +-----------+             +-----------+
#  | node_4444 +-------------+ node_3333 |
#  |    FUNDER |             |           |
#  +-----------+             |    fundee |
#                            +-----------+

# connect
./ptarmcli -c conf/peer3333.conf 4445

sleep 5

# node_4444からnode_3333へチャネルを開く。
./fund-test-in.sh > node_4444/fund4444_3333.conf
./ptarmcli -c conf/peer3333.conf -f node_4444/fund4444_3333.conf 4445

# 少し待つ
echo wait...
sleep 10

# mining
bitcoin-cli -conf=`pwd`/regtest.conf -datadir=`pwd` generate 6

# 少し待つ
echo wait............
sleep 10

while :
do
    CHN3=`./showdb -c -d node_3333 | jq '.[]|length'`
    CHN4=`./showdb -c -d node_4444 | jq '.[]|length'`
    NOD3=`./showdb -n -d node_3333 | jq '.[]|length'`
    NOD4=`./showdb -n -d node_4444 | jq '.[]|length'`
    echo CHAN3=$CHN3:$NOD3 CHAN4=$CHN4:$NOD4

    if [ "$CHN3" -eq 3 ] && [ "$CHN4" -eq 3 ] && [ "$NOD3" -eq 2 ] && [ "$NOD4" -eq 2 ]; then
        break
    fi
    PTARMS3333=`./ptarmcli -l 3334 | grep -c node_id`
    PTARMS4444=`./ptarmcli -l 4445 | grep -c node_id`
    if [ ${PTARMS3333} -ne 1 ] || [ ${PTARMS4444} -ne 1 ]; then
        echo ptarmd exited
        exit 1
    fi
    sleep 3
done

echo @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
echo @ channel established
echo @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
