#!/bin/sh
PAY_BEGIN=4444
PAY_END=6666
AMOUNT=100000
PAYER_PORT=$(( ${PAY_BEGIN} + 1 ))

# create invalid realm onion
./ptarmcli --debug 16 $PAYER_PORT

./example_st4pay_r.sh $PAY_BEGIN $PAY_END $AMOUNT $1

sleep 2

# reset
./ptarmcli --debug 16 $PAYER_PORT
