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
