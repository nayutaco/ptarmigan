#!/bin/sh
set -ue
NETTYPE=regtest

cd node_3333
echo @[node_3333]@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
../showdb $NETTYPE wallet | jq '.'
cd ../node_4444
echo @[node_4444]@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
../showdb $NETTYPE wallet | jq '.'
cd ../node_5555
echo @[node_5555]@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
../showdb $NETTYPE wallet | jq '.'
cd ../node_6666
echo @[node_6666]@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
../showdb $NETTYPE wallet | jq '.'
cd ..
