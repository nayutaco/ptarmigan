#!/bin/sh
PAY_BEGIN=4444
PAY_END=3333
AMOUNT=100000

echo "-------------------------------"
echo "PAY small: 4444-->3333"
echo "-------------------------------"

./example_st4pay_r.sh $PAY_BEGIN $PAY_END $AMOUNT
