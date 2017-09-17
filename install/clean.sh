#!/bin/sh
bitcoin-cli -conf=`pwd`/regtest.conf -datadir=`pwd`/regtest stop
sleep 1
rm -rf *.cnl node_3333 node_4444 node_5555 conf pay4444_3333_5555.conf routing.dot regtest
