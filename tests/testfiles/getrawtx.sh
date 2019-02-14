#!/bin/sh
bitcoin-cli -conf=`pwd`/regtest.conf -datadir=`pwd` getrawtransaction $1 $2
