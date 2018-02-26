#!/bin/sh

PORT=$3

if [ ${#1} != 66 ] || [ -z "$2" ]; then
    echo "create_knownpeers.sh <peer node_id> <ipaddr>"
    exit 1
fi
if [ -z "$PORT" ]; then
    PORT=9735
fi

echo node_id=$1
echo ipaddr=$2
echo port=$PORT
