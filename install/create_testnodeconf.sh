#!/bin/sh

if [ -z $1 ]; then
    echo "./create_testnodeconf.sh <port>"
    exit 1
fi

WIF=`./ucoind wif`

echo port=$1
echo name=ptarm_$1
echo $WIF
echo ipv4=127.0.0.1
echo rpcuser=bitcoinuser
echo rpcpasswd=bitcoinpassword
echo rpcurl=127.0.0.1
echo rpcport=18443
