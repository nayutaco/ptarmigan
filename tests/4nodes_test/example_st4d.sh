#!/bin/sh
PAY_BEGIN=6666
PAY_END=4444
AMOUNT=100000

echo "--------------------------------------------"
echo "PAY small: 6666 --> 5555 --> 3333 --> 4444"
echo "--------------------------------------------"

./example_st4pay_r.sh $PAY_BEGIN $PAY_END $AMOUNT $1
