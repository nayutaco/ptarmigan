#!/bin/sh

killall ucoind
cd node_3333
../ucoind node.conf > log.log 2>&1 &
cd .. 
cd node_4444
../ucoind node.conf > log.log 2>&1 &
cd ..
cd node_5555
../ucoind node.conf > log.log 2>&1 &
cd ..
cd node_6666
../ucoind node.conf > log.log 2>&1 &
cd ..

sleep 1

# ノード接続
#
./ucoincli -c conf/peer4444.conf 3334
./ucoincli -c conf/peer5555.conf 3334
./ucoincli -c conf/peer3333.conf 6667
