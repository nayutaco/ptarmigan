#!/bin/bash

msat3=0
msat4=0

amount() {
    echo `./ptarmcli -l $1 | jq -e '.result.total_local_msat'`
}

get_amount() {
    msat3=`amount 3334`
    msat4=`amount 4445`
    echo msat3=${msat3} msat4=${msat4}
}

check_amount() {
    msat3_after=`amount 3334`
    msat4_after=`amount 4445`
    echo msat3=${msat3_after} msat4=${msat4_after}
    if [ $# -eq 1 ] && [ "$1" == "same" ]; then
        if [ ${msat3} -ne ${msat3_after} ]; then
            echo invalid amount3: != ${msat3}
            exit 1
        fi
        if [ ${msat4} -ne ${msat4_after} ]; then
            echo invalid amount4: != ${msat4}
            exit 1
        fi
    else
        if [ ${msat3} -eq ${msat3_after} ]; then
            echo invalid amount3: == ${msat3}
            exit 1
        fi
        if [ ${msat4} -eq ${msat4_after} ]; then
            echo invalid amount4: == ${msat4}
            exit 1
        fi
    fi
    msat3=${msat3_after}
    msat4=${msat4_after}
}


echo node_3333 no-fulfill return
./ptarmcli --debug 1 3334

echo st4e start
./example_st4e.sh
sleep 5 # XXX: TODO
check_amount
echo st4e end

echo quit 3333
./ptarmcli -q 3334
sleep 3

echo unilateral close from 4444
./ptarmcli -c conf/peer3333.conf -xforce 4445

echo デフォルトではinvoiceのmin_final_cltv_expiryは9で、オフセットも含めると19になっている。
echo 次のgenerateでcommit_txがminingされ、さらに18generateするとHTLC Timeout Txを展開。
echo spending to_local output txは、to_self_delayが40なので40confでspendableになる。
echo 監視周期が30秒なので、そこを気にしながら見ていく。

./generate.sh 1
sleep 30
echo ---------- commit_tx conf=1 ---------------
./ptarmcli --getinfo 4445
P2W=`./ptarmcli --paytowallet 4445`
echo ${P2W} | jq .
AMOUNT=`echo ${P2W} | jq -r -e '.result.wallet.amount'`
if [ ${AMOUNT} -ne 0 ]; then
    echo ERROR: amount != 0
    exit 0
fi
LIST=`echo ${P2W} | jq -r -e '.result.list | length'`
if [ ${LIST} -ne 1 ]; then
    echo ERROR: list.len != 1
    exit 0
fi
echo ---------- OK: commit_tx conf=1 ---------------

./generate.sh 18
sleep 30
echo ---------- commit_tx conf=19, HTLC_TO_tx conf=0 ---------------
./ptarmcli --getinfo 4445
P2W=`./ptarmcli --paytowallet 4445`
echo ${P2W} | jq .
AMOUNT=`echo ${P2W} | jq -r -e '.result.wallet.amount'`
if [ ${AMOUNT} -ne 0 ]; then
    echo ERROR: amount != 0
    exit 0
fi
LIST=`echo ${P2W} | jq -r -e '.result.list | length'`
if [ ${LIST} -eq 2 ]; then
    echo OK if bitcoind version
elif [ ${LIST} -eq 1 ]; then
    echo OK if bitcoinj version
else
    echo ERROR: list.len=${LIST}
    exit 0
fi
echo ---------- OK: commit_tx conf=19, HTLC_TO_tx conf=0 ---------------

./generate.sh 1
sleep 30
echo ---------- commit_tx conf=20, HTLC_TO_tx conf=1 ---------------
./ptarmcli --getinfo 4445
P2W=`./ptarmcli --paytowallet 4445`
echo ${P2W} | jq .
AMOUNT=`echo ${P2W} | jq -r -e '.result.wallet.amount'`
if [ ${AMOUNT} -ne 0 ]; then
    echo ERROR: amount != 0
    exit 0
fi
LIST=`echo ${P2W} | jq -r -e '.result.list | length'`
if [ ${LIST} -ne 2 ]; then
    echo ERROR: list.len != 2
    exit 0
fi
echo ---------- OK: commit_tx conf=20, HTLC_TO_tx conf=1 ---------------

./generate.sh 20
sleep 30
echo ---------- commit_tx conf=40, HTLC_TO_tx conf=21 ---------------
./ptarmcli --getinfo 4445
P2W=`./ptarmcli --paytowallet 4445`
echo ${P2W} | jq .
AMOUNT=`echo ${P2W} | jq -r -e '.result.wallet.amount'`
if [ ${AMOUNT} -eq 0 ]; then
    echo ERROR: amount == 0
    exit 0
fi
LIST=`echo ${P2W} | jq -r -e '.result.list | length'`
if [ ${LIST} -ne 2 ]; then
    echo ERROR: list.len != 2
    exit 0
fi
echo ---------- OK: commit_tx conf=40, HTLC_TO_tx conf=21 ---------------

echo ---------- spned: to_local output ---------------
P2W=`./ptarmcli --paytowallet=1 4445`
echo ${P2W} | jq .
AMOUNT=`echo ${P2W} | jq -r -e '.result.wallet.amount'`
if [ ${AMOUNT} -eq 0 ]; then
    echo ERROR: amount == 0
    exit 0
fi
LIST=`echo ${P2W} | jq -r -e '.result.list | length'`
if [ ${LIST} -ne 2 ]; then
    echo ERROR: list.len != 2
    exit 0
fi
echo ---------- OK: spned: to_local output ---------------

echo ---------- after spend: to_local output ---------------
P2W=`./ptarmcli --paytowallet 4445`
echo ${P2W} | jq .
AMOUNT=`echo ${P2W} | jq -r -e '.result.wallet.amount'`
if [ ${AMOUNT} -ne 0 ]; then
    echo ERROR: amount != 0
    exit 0
fi
LIST=`echo ${P2W} | jq -r -e '.result.list | length'`
if [ ${LIST} -ne 1 ]; then
    echo ERROR: list.len != 1
    exit 0
fi
echo ---------- OK: after spend: to_local output ---------------

./generate.sh 8
sleep 30
echo ---------- HTLC_TO_tx conf=29 ---------------
./ptarmcli --getinfo 4445
P2W=`./ptarmcli --paytowallet 4445`
echo ${P2W} | jq .
AMOUNT=`echo ${P2W} | jq -r -e '.result.wallet.amount'`
if [ ${AMOUNT} -ne 0 ]; then
    echo ERROR: amount != 0
    exit 0
fi
LIST=`echo ${P2W} | jq -r -e '.result.list | length'`
if [ ${LIST} -ne 1 ]; then
    echo ERROR: list.len != 1
    exit 0
fi
echo ---------- OK: HTLC_TO_tx conf=29 ---------------

./generate.sh 1
sleep 30
echo ---------- HTLC_TO_tx conf=30 ---------------
./ptarmcli --getinfo 4445
P2W=`./ptarmcli --paytowallet 4445`
echo ${P2W} | jq .
AMOUNT=`echo ${P2W} | jq -r -e '.result.wallet.amount'`
if [ ${AMOUNT} -eq 0 ]; then
    echo ERROR: amount == 0
    exit 0
fi
LIST=`echo ${P2W} | jq -r -e '.result.list | length'`
if [ ${LIST} -ne 1 ]; then
    echo ERROR: list.len != 1
    exit 0
fi
echo ---------- OK: HTLC_TO_tx conf=30 ---------------

echo ---------- spned: HTLC_tx ---------------
P2W=`./ptarmcli --paytowallet=1 4445`
echo ${P2W} | jq .
AMOUNT=`echo ${P2W} | jq -r -e '.result.wallet.amount'`
if [ ${AMOUNT} -eq 0 ]; then
    echo ERROR: amount == 0
    exit 0
fi
LIST=`echo ${P2W} | jq -r -e '.result.list | length'`
if [ ${LIST} -ne 1 ]; then
    echo ERROR: list.len != 1
    exit 0
fi
echo ---------- OK: spned: HTLC_tx ---------------

echo ---------- after spned: HTLC_tx ---------------
P2W=`./ptarmcli --paytowallet 4445`
echo ${P2W} | jq .
AMOUNT=`echo ${P2W} | jq -r -e '.result.wallet.amount'`
if [ ${AMOUNT} -ne 0 ]; then
    echo ERROR: amount != 0
    exit 0
fi
LIST=`echo ${P2W} | jq -r -e '.result.list | length'`
if [ ${LIST} -ne 0 ]; then
    echo ERROR: list.len != 0
    exit 0
fi
echo ---------- OK: after spned: HTLC_tx ---------------
