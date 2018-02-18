#!/bin/sh

killall ucoind
cd node_3333
../ucoind -c ../regtest.conf &
cd .. 
cd node_4444
../ucoind -c ../regtest.conf&
cd ..
cd node_5555
../ucoind -c ../regtest.conf&
cd ..
cd node_6666
../ucoind -c ../regtest.conf&
cd ..

sleep 1

# ノード接続
#
./ucoincli -c conf/peer4444.conf 3334
./ucoincli -c conf/peer5555.conf 3334
./ucoincli -c conf/peer5555.conf 6667
