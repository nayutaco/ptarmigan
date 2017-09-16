#!/bin/sh
set -eu
NETTYPE=regtest

cd node_3333
echo @[node_3333]@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
../showdb $NETTYPE self | jq '.'
cd ../node_4444
echo @[node_4444]@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
../showdb $NETTYPE self | jq '.'
cd ../node_5555
echo @[node_5555]@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
../showdb $NETTYPE self | jq '.'
cd ../..
