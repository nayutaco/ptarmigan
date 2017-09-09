#!/bin/sh
set -eu

cd node_3333
echo @[node_3333]@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
../showdb self | jq '.'
cd ../node_4444
echo @[node_4444]@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
../showdb self | jq '.'
cd ../node_5555
echo @[node_5555]@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
../showdb self | jq '.'
cd ../..
