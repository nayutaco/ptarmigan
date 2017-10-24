#!/bin/sh
set -ue

echo port=$1
echo name=node_$1
WIF=`./ucoind wif`
echo $WIF
