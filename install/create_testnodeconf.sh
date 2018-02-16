#!/bin/bash

if [ -z $1 ]; then
    echo "./create_testnodeconf.sh <port>"
    exit 1
fi

echo port=$1
echo ipv4=127.0.0.1
echo rpcuser=bitcoinuser
echo rpcpasswd=bitcoinpassword
echo rpcurl=127.0.0.1
echo rpcport=18443
