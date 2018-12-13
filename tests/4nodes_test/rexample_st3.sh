#!/bin/sh
# SPV用

mkdir -p conf
rm -rf conf/*.conf
mv node_3333/ptarm_*.conf conf/peer3333.conf
mv node_4444/ptarm_*.conf conf/peer4444.conf
mv node_5555/ptarm_*.conf conf/peer5555.conf
mv node_6666/ptarm_*.conf conf/peer6666.conf

# connect
./ptarmcli -c conf/peer3333.conf 4445
sleep 1
./ptarmcli -c conf/peer3333.conf 5556
sleep 1
./ptarmcli -c conf/peer5555.conf 6667
sleep 1

# charge
NEWADDR=`./ptarmcli --getnewaddress 4445 | jq -e '.[]' -r`
bitcoin-cli -conf=`pwd`/regtest.conf -datadir=`pwd` sendtoaddress $NEWADDR 0.1
NEWADDR=`./ptarmcli --getnewaddress 5556 | jq -e '.[]' -r`
bitcoin-cli -conf=`pwd`/regtest.conf -datadir=`pwd` sendtoaddress $NEWADDR 0.1
NEWADDR=`./ptarmcli --getnewaddress 6667 | jq -e '.[]' -r`
bitcoin-cli -conf=`pwd`/regtest.conf -datadir=`pwd` sendtoaddress $NEWADDR 0.1

bitcoin-cli -conf=`pwd`/regtest.conf -datadir=`pwd` generate 1

# node_4444からnode_3333へチャネルを開く。
./ptarmcli -c conf/peer3333.conf -f 600000,300000 4445

sleep 3

# node_5555からnode_3333へチャネルを開く。
./ptarmcli -c conf/peer3333.conf -f 600000,300000 5556

sleep 3

# node_6666からnode_5555へチャネルを開く。
./ptarmcli -c conf/peer5555.conf -f 600000,300000 6667

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
    ./showdb -c -d node_5555 | jq '.' > n5.txt
    ./showdb -c -d node_6666 | jq '.' > n6.txt
    cmp n3.txt n4.txt
    RES1=$?
    cmp n3.txt n5.txt
    RES2=$?
    cmp n3.txt n6.txt
    RES3=$?

    LEN3=`cat n3.txt | jq length`
    LEN4=`cat n4.txt | jq length`
    LEN5=`cat n5.txt | jq length`
    LEN6=`cat n6.txt | jq length`

    if [ -n "$LEN3" ] && [ -n "$LEN4" ] && [ -n "$LEN5" ] && [ -n "$LEN6" ] && [ "$LEN3" -ne 0 ] && [ "$LEN4" -ne 0 ] && [ "$LEN5" -ne 0 ] && [ "$LEN6" -ne 0 ] && [ "$RES1" -eq 0 ] && [ "$RES2" -eq 0 ] && [ "$RES3" -eq 0 ]; then
        break
    fi
    sleep 3
done

#rm n3.txt n4.txt n5.txt n6.txt

echo @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
echo @ channel established
echo @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
