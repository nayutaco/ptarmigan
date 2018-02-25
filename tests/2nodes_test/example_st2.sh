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
cd ..

sleep 1
