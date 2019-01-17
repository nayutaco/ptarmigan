#!/bin/sh
#
#
#  +-----------+             +-----------+
#  | node_4444 +-------------+ node_3333 |
#  |    FUNDER |             |           |
#  +-----------+             |    fundee |
#                            +-----------+

mkdir -p conf
rm -rf conf/*.conf
mv node_3333/ptarm_*.conf conf/peer3333.conf
mv node_4444/ptarm_*.conf conf/peer4444.conf

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
    ./showdb -c -d node_3333 | jq '.[][].short_channel_id' > n3.txt
    ./showdb -c -d node_4444 | jq '.[][].short_channel_id' > n4.txt
    cmp n3.txt n4.txt
    RES1=$?

    LEN3=`cat n3.txt | wc -c`
    LEN4=`cat n4.txt | wc -c`

    if [ "$LEN3" -ne 0 ] && [ "$LEN4" -ne 0 ] && [ $RES1 -eq 0 ]; then
        break
    fi
    sleep 3
done

#rm n3.txt n4.txt

echo @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
echo @ channel established
echo @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
