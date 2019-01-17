#!/bin/sh -ue
# amount appear in commit_tx
PAY_BEGIN=4444
PAY_END=6666
AMOUNT=200000000

echo "--------------------------------------------"
echo "PAY large: 4444 --> 3333 --> 5555 --> 6666"
echo "--------------------------------------------"

./example_st4pay_r.sh $PAY_BEGIN $PAY_END $AMOUNT
