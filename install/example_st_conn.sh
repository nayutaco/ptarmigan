#!/bin/sh

pushd node_3333 ; ../ucoind node.conf ; popd
pushd node_4444 ; ../ucoind node.conf ; popd
pushd node_5555 ; ../ucoind node.conf ; popd

# ノード接続
#
./ucoincli -c conf/peer4444.conf 3333
./ucoincli -c conf/peer5555.conf 3333
