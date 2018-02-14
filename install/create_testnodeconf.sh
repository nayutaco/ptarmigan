#!/bin/bash

if [ -z $1 ]; then
    echo "./create_testnodeconf.sh <port>"
    exit 1
fi

WIFS=`./ucoind wif`
set $WIFS
WIF=$1
PUB=$2

echo port=$1
echo name=node_${PUB:0:12}
echo wif=$WIF
echo ipv4=127.0.0.1
echo rpcuser=bitcoinuser
echo rpcpasswd=bitcoinpassword
echo rpcurl=127.0.0.1
echo rpcport=18443
