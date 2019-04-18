#!/bin/bash -ue

if [ -z "$1" ] || [ -z "$2" ]; then
	echo invalid parameter [$1] [$2]
	echo [node] [feerate_per_kw]
	exit 128
fi

NODE=node_$1
NODE_PORT=$(( $1 + 1 ))
FEERATE_PER_KW=$2


update_fee() {
	echo "feerate_per_kw $FEERATE_PER_KW"
	echo "port $NODE_PORT"

	./ptarmcli --setfeerate $FEERATE_PER_KW $NODE_PORT
	if [ $? -ne 0 ]; then
		echo fail update_fee
		exit 2
	fi
}

update_fee
