#!/bin/sh
set -ue

cd node_3333
echo @[node_3333]@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
../showdb wallet | jq '.'
cd ../node_4444
echo @[node_4444]@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
../showdb wallet | jq '.'
cd ../node_5555
echo @[node_5555]@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
../showdb wallet | jq '.'
cd ..
