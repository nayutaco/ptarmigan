#!/bin/sh
set -eu
bitcoin-cli -conf=`pwd`/regtest.conf -datadir=`pwd` generate $1
