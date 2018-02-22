#!/bin/sh

# ノードの起動
#
# ここでは連続して起動させているが、動作を見る場合にはコンソールをそれぞれ開き、
# 各コンソールで起動させた方がログを見やすい。
cd node_3333
rm -rf dbucoin
../ucoind -c ../regtest.conf -p 3333 &
cd ../node_4444
rm -rf dbucoin
../ucoind -c ../regtest.conf -p 4444 &
cd ../node_5555
rm -rf dbucoin
../ucoind -c ../regtest.conf -p 5555 &
cd ../node_6666
rm -rf dbucoin
../ucoind -c ../regtest.conf -p 6666 &
cd ..

sleep 3

mkdir -p conf
mv node_3333/peer_*.conf conf/peer3333.conf
mv node_4444/peer_*.conf conf/peer4444.conf
mv node_5555/peer_*.conf conf/peer5555.conf
mv node_6666/peer_*.conf conf/peer6666.conf
