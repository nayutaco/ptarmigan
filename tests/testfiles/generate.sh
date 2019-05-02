#!/bin/sh
set -eu
ADDR=`bitcoin-cli -conf=$PWD/regtest.conf -datadir=$PWD getnewaddress`
bitcoin-cli -conf=$PWD/regtest.conf -datadir=$PWD generatetoaddress $1 $ADDR
