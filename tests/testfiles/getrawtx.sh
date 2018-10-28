#!/bin/sh
set -eu
bitcoin-cli -conf=`pwd`/regtest.conf -datadir=`pwd` getrawtransaction $1
