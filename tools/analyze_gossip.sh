#!/bin/bash

if [ $# -ne 1 ]; then
	echo "need showdb path"
	exit 1
fi

SHOWDB=$1/showdb

#allnum=`${SHOWDB} -c | jq -e '.[] | length'`
#echo "all= $allnum"

num_chan=`${SHOWDB} -c | grep -w -c "channel_announcement"`
num_upd0=`${SHOWDB} -c | grep -w -c "channel_update 0"`
num_upd1=`${SHOWDB} -c | grep -w -c "channel_update 1"`
num_node=`${SHOWDB} -n | grep -w -c "node"`
echo "channel_announcement= $num_chan"
echo "channel_update 0= $num_upd0"
echo "channel_update 1= $num_upd1"
echo "node_announcement= $num_node"
