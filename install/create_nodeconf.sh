#!/bin/sh
set -ue

echo port=$1
echo name=node_$1
WIF=`./ucoind wif`
echo $WIF
echo rpcuser=bitcoinuser
echo rpcpasswd=bitcoinpassword
echo rpcurl=http://127.0.0.1:18332/
