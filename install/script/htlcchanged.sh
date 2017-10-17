#!/bin/sh
echo $(date +%c) $(date +%N)
echo CHANGED $1 $2
../showdb regtest w | jq .
