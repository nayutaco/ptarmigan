#!/bin/bash

PORT=9735
if [ $# -gt 0 ]; then
    PORT=$1
fi

WIFS=`./ucoind wif`
set $WIFS
WIF=$1
PUB=$2

echo port=$PORT
echo name=node_${PUB:0:12}
echo wif=$WIF
