#!/bin/sh
set -eu

echo ipaddr=127.0.0.1
echo port=$1
NODE=`./ucoind $2 id`
echo node_id=$NODE
