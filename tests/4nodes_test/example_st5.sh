#!/bin/sh -ue

# チャネルをクローズする。
# 今のところ、Mutual Closeのみ実装している。
# P2PKHアドレスに送金しているため、bitcoindで検出可能なはずである。
#
# チャネルを閉じてもノードとして機能するため、ptarmdは起動したままになる。
# DBからのチャネル情報削除は、gettxout によって funding_txが unspentではなくなったことを確認してから行っている。
./ptarmcli -c conf/peer3333.conf -x 4445
./ptarmcli -c conf/peer3333.conf -x 5556
./ptarmcli -c conf/peer5555.conf -x 6667

# mining
sleep 3
./generate.sh 1

loop=1
while [ $loop -eq 1 ];
do
    loop=0
    for i in 3333 4444 5555 6666
    do
        TMPFILE=./tmp.st5
        ./showdb -d node_$i -s >$TMPFILE || (ERR=$?; echo showdb failed=$ERR; exit $ERR)
        cnt=`cat $TMPFILE | jq -e 'length'`
        if [ $cnt -eq 0 ]; then
            echo node_$i DB closed
        else
            echo node_$i not DB closed
            sleep 5
            loop=1
        fi
    done
done

loop=1
while [ $loop -eq 1 ];
do
    loop=0
    for i in 3334 4445 5556 6667
    do
        cnt=`./ptarmcli -l $i | jq -e '.result.peers | length'`
        if [ $cnt -eq 0 ]; then
            echo node_$i closed
        else
            echo node_$i not closed
            sleep 5
            loop=1
        fi
    done
done