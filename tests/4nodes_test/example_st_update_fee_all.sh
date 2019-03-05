#!/bin/bash -ue

if [ -z "$1" ]; then
	echo invalid parameter [$1]
	echo [feerate_per_kw]
	exit 128
fi

FEERATE_PER_KW=$1


for i in 3333 4444 5555 6666
do
    ./example_st_update_fee.sh $i $FEERATE_PER_KW
done
