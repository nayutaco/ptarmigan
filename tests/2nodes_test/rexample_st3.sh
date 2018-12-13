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

# charge
NEWADDR=`./ptarmcli --getnewaddress 4445 | jq -e '.[]' -r`
bitcoin-cli -conf=`pwd`/regtest.conf -datadir=`pwd` sendtoaddress $NEWADDR 0.1
bitcoin-cli -conf=`pwd`/regtest.conf -datadir=`pwd` generate 1

# connect
./ptarmcli -c conf/peer3333.conf 4445

sleep 5

# node_4444からnode_3333へチャネルを開く。
./ptarmcli -c conf/peer3333.conf -f 600000 4445

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
    ./showdb -c -d node_3333 | jq '.' > n3.txt
    ./showdb -c -d node_4444 | jq '.' > n4.txt
    cmp n3.txt n4.txt
    RES1=$?

    LEN3=`cat n3.txt | jq length`
    LEN4=`cat n4.txt | jq length`

    if [ "$LEN3" -ne 0 ] && [ "$LEN4" -ne 0 ] && [ $RES1 -eq 0 ]; then
        break
    fi
    sleep 3
done

#rm n3.txt n4.txt

echo @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
echo @ channel established
echo @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
