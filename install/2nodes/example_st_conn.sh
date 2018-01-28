#!/bin/sh

killall ucoind
cd node_3333
../ucoind node.conf&
cd .. 
cd node_4444
../ucoind node.conf&
cd ..

sleep 1

# ノード接続
#
./ucoincli -c conf/peer4444.conf 3334
