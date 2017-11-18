#!/bin/sh

# チャネルをクローズする。
# 今のところ、Mutual Closeのみ実装している。
# P2PKHアドレスに送金しているため、bitcoindで検出可能なはずである。
#
# チャネルを閉じてもノードとして機能するため、ucoindは起動したままになる。
# DBからのチャネル情報削除は、gettxout によって funding_txが unspentではなくなったことを確認してから行っている。
./ucoincli -c conf/peer3333.conf -x 4445
./ucoincli -c conf/peer3333.conf -x 5556
./ucoincli -c conf/peer5555.conf -x 6667
# sleep 3

# bitcoin-cli -conf=`pwd`/regtest.conf -datadir=`pwd`/regtest stop

# ./ucoincli -q 3334
# ./ucoincli -q 4445
# ./ucoincli -q 5556
# ./ucoincli -q 6667
