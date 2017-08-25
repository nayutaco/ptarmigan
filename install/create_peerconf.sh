#!/bin/sh
set -eu

echo ipaddr=127.0.0.1
echo `cat $1 | sed -n "1,1p"`
NODE=`./ucoind $1 id`
echo node_id=$NODE
