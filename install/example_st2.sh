#!/bin/sh

# ノードの起動
#
# ここでは連続して起動させているが、動作を見る場合にはコンソールをそれぞれ開き、
# 各コンソールで起動させた方がログを見やすい。
cd node_3333
../ucoind node.conf &
cd ../node_4444
../ucoind node.conf &
cd ../node_5555
../ucoind node.conf &
cd ../node_6666
../ucoind node.conf &
cd ..
