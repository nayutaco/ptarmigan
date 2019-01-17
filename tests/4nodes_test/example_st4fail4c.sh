#!/bin/sh
#	onion error "invalid realm"(4444)

PAY_BEGIN=4444
PAY_END=6666
AMOUNT=100000
PAYER_PORT=$(( ${PAY_BEGIN} + 1 ))

echo "--------------------------------------------"
echo "PAY FAIL: 4444 --> 3333 --> 5555 --> 6666"
echo "    create invalid realm onion"
echo "--------------------------------------------"

# create invalid realm onion
./ptarmcli --debug 16 $PAYER_PORT

./example_st4pay_r.sh $PAY_BEGIN $PAY_END $AMOUNT $1

read -p "Hit ENTER Key!" key

# reset
./ptarmcli --debug 16 $PAYER_PORT
