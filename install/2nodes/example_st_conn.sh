#!/bin/sh

killall ucoind
cd node_3333
../ucoind -c ../regtest.conf&
cd .. 
cd node_4444
../ucoind -c ../regtest.conf&
cd ..

sleep 1

# ノード接続
#
./ucoincli -c conf/peer4444.conf 3334
