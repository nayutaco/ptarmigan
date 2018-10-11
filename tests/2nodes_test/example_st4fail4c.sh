#!/bin/sh
#   PAYERが不正なrealmのonionを作成する

echo "-------------------------------"
echo "NO_FULFILL: 4444-->3333"
echo "   create invalid realm onion"
echo "-------------------------------"

PAY_BEGIN=4444
PAY_END=3333
AMOUNT=100000
PAYER_PORT=$(( ${PAY_BEGIN} + 1 ))

# create invalid realm onion
./ptarmcli --debug 16 $PAYER_PORT

./example_st4pay_r.sh $PAY_BEGIN $PAY_END $AMOUNT

read -p "Hit ENTER Key!" key

# reset
./ptarmcli --debug 16 $PAYER_PORT
