#!/bin/sh
#   PAYERが不正なversionのonionを作成する

PAY_BEGIN=4444
PAY_END=3333
AMOUNT=100000
PAYER_PORT=$(( ${PAY_BEGIN} + 1 ))

# create invalid version onion
./ptarmcli --debug 32 $PAYER_PORT

./example_st4pay_r.sh $PAY_BEGIN $PAY_END $AMOUNT

sleep 2

# reset
./ptarmcli --debug 32 $PAYER_PORT
