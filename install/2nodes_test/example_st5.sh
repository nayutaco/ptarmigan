#!/bin/sh

# チャネルをクローズする。
# 今のところ、Mutual Closeのみ実装している。
# P2PKHアドレスに送金しているため、bitcoindで検出可能なはずである。
#
# チャネルを閉じてもノードとして機能するため、ucoindは起動したままになる。
# DBからのチャネル情報削除は、gettxout によって funding_txが unspentではなくなったことを確認してから行っている。
./ucoincli -c conf/peer3333.conf -x 4445

# mining
sleep 3
./generate.sh 1
