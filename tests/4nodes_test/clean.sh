#!/bin/sh
bash kill_ptarmd.sh
bitcoin-cli -conf=`pwd`/regtest.conf -datadir=`pwd`/regtest stop
sleep 1
rm -rf \
    *.cnl \
    node_3333 node_4444 node_5555 node_6666 \
    conf pay_*.conf routing.dot routing.png regtest *.log n?.txt anno.conf channel.conf \
    tmp.*

# remove synbolic link
rm ptarmcli ptarmd showdb routing regtest.conf generate.sh getrawtx.sh sendrawtx.sh default_conf.sh kill_ptarmd.sh
