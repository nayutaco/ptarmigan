#!/bin/sh
set -eu

ADDR=`bitcoin-cli -conf=$PWD/regtest.conf -datadir=$PWD getnewaddress`
bitcoin-cli -datadir=$PWD -conf=$PWD/regtest.conf generatetoaddress $1 $ADDR
echo ---------- generate=$1 blockcount=`bitcoin-cli -datadir=$PWD -conf=$PWD/regtest.conf getblockcount` ---------------
