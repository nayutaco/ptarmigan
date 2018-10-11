#!/bin/sh
#   PAYERが不正なversionのonionを作成する

echo "-------------------------------"
echo "NO_FULFILL: 4444-->3333"
echo "    create invalid version onion"
echo "-------------------------------"

PAY_BEGIN=4444
PAY_END=3333
AMOUNT=100000
PAYER_PORT=$(( ${PAY_BEGIN} + 1 ))

# create invalid version onion
./ptarmcli --debug 32 $PAYER_PORT

./example_st4pay_r.sh $PAY_BEGIN $PAY_END $AMOUNT

read -p "Hit ENTER Key!" key

# reset
./ptarmcli --debug 32 $PAYER_PORT
