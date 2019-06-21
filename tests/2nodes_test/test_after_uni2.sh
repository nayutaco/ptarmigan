#!/bin/bash
set -eu

msat3=0
msat4=0

getblockcount() {
    echo `bitcoin-cli -datadir=$PWD -conf=$PWD/regtest.conf getblockcount`
}

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

TARGET_NODE=3334

echo quit 4444
./ptarmcli -q 4445
sleep 3

BASECOUNT=`getblockcount`
echo BASECOUNT=${BASECOUNT}

echo unilateral close from 3333
./ptarmcli -c conf/peer4444.conf -xforce ${TARGET_NODE}

echo 4444がoffered HTLC、3333がreceived HTLCを持った状態。
echo unilateral closeを3333が行い、3333を確認していく\(local unilateral close\)。4444はkill済み。
echo    to_self_delay: node_3333=30, node_4444=31
echo
echo 次のgenerateでcommit_txがminingされるが、preimageを持っているのでHTLC success TXを展開。
echo spending to_local output txは、to_self_delayが31なので31confでspendableになる。

# (alpha=438)
# blockcount: alpha
#       local commit_tx broadcast
# blockcount: alpha+1
#       commit_tx conf=1
#       received HTLC ==> HTLC success tx broadcast
# blockcount: alpha+2
#       commit_tx conf=2
#       HTLC_tx conf=1
#
# ...
#
# blockcount: alpha+31
#       commit_tx conf=31 ==> spendable
#       HTLC_tx conf=30
# blockcount: alpha+32
#       HTLC_tx conf=31 ==> spendable


./generate.sh 1
sleep 30
echo ---------- commit_tx conf=1 ---------------
./ptarmcli --getinfo ${TARGET_NODE}
P2W=`./ptarmcli --paytowallet ${TARGET_NODE}`
echo ${P2W} | jq .
AMOUNT=`echo ${P2W} | jq -r -e '.result.wallet.amount'`
if [ ${AMOUNT} -ne 0 ]; then
    echo ERROR: amount != 0
    exit 1
fi
LIST=`echo ${P2W} | jq -r -e '.result.list | length'`
if [ ${LIST} -ne 2 ]; then
    echo ERROR: list.len != 2
    exit 1
fi
echo ---------- OK: commit_tx conf=1 ---------------

./generate.sh 1
sleep 30
echo ---------- commit_tx conf=2, HTLC_tx conf=1 ---------------
./ptarmcli --getinfo ${TARGET_NODE}
P2W=`./ptarmcli --paytowallet ${TARGET_NODE}`
echo ${P2W} | jq .
AMOUNT=`echo ${P2W} | jq -r -e '.result.wallet.amount'`
if [ ${AMOUNT} -ne 0 ]; then
    echo ERROR: amount != 0
    exit 1
fi
LIST=`echo ${P2W} | jq -r -e '.result.list | length'`
if [ ${LIST} -ne 2 ]; then
    echo ERROR: list.len != 2
    exit 1
fi
echo ---------- OK: commit_tx conf=1 ---------------

./generate.sh 28
sleep 30
echo ---------- commit_tx conf=30, HTLC_tx conf=29 ---------------
./ptarmcli --getinfo ${TARGET_NODE}
P2W=`./ptarmcli --paytowallet ${TARGET_NODE}`
echo ${P2W} | jq .
AMOUNT=`echo ${P2W} | jq -r -e '.result.wallet.amount'`
if [ ${AMOUNT} -ne 0 ]; then
    echo ERROR: amount != 0
    exit 1
fi
LIST=`echo ${P2W} | jq -r -e '.result.list | length'`
if [ "$1" == "BITCOIND" ] && [ ${LIST} -eq 2 ]; then
    echo OK if bitcoind version
elif [ "$1" == "BITCOINJ" ] && [ ${LIST} -eq 1 ]; then
    echo OK if bitcoinj version
else
    echo ERROR: list.len=${LIST}
    exit 1
fi
echo ---------- OK: commit_tx conf=30, HTLC_tx conf=29 ---------------

./generate.sh 1
sleep 30
echo ---------- commit_tx conf=31, HTLC_tx conf=30 ---------------
./ptarmcli --getinfo ${TARGET_NODE}
P2W=`./ptarmcli --paytowallet ${TARGET_NODE}`
echo ${P2W} | jq .
AMOUNT=`echo ${P2W} | jq -r -e '.result.wallet.amount'`
if [ ${AMOUNT} -eq 0 ]; then
    echo ERROR: amount == 0
    exit 1
fi
LIST=`echo ${P2W} | jq -r -e '.result.list | length'`
if [ ${LIST} -ne 2 ]; then
    echo ERROR: list.len != 2
    exit 1
fi
echo ---------- OK: commit_tx conf=31, HTLC_tx conf=30 ---------------

echo ---------- spend: to_local output ---------------
P2W=`./ptarmcli --paytowallet=1 ${TARGET_NODE}`
echo ${P2W} | jq .
AMOUNT=`echo ${P2W} | jq -r -e '.result.wallet.amount'`
if [ ${AMOUNT} -eq 0 ]; then
    echo ERROR: amount == 0
    exit 1
fi
LIST=`echo ${P2W} | jq -r -e '.result.list | length'`
if [ ${LIST} -ne 2 ]; then
    echo ERROR: list.len != 2
    exit 1
fi
echo ---------- OK: spend: to_local output ---------------

echo ---------- after spend: to_local output ---------------
P2W=`./ptarmcli --paytowallet ${TARGET_NODE}`
echo ${P2W} | jq .
AMOUNT=`echo ${P2W} | jq -r -e '.result.wallet.amount'`
if [ ${AMOUNT} -ne 0 ]; then
    echo ERROR: amount != 0
    exit 1
fi
LIST=`echo ${P2W} | jq -r -e '.result.list | length'`
if [ ${LIST} -ne 1 ]; then
    echo ERROR: list.len != 1
    exit 1
fi
echo ---------- OK: after spend: to_local output ---------------

./generate.sh 1
sleep 30
echo ---------- HTLC_tx conf=31 ---------------
./ptarmcli --getinfo ${TARGET_NODE}
P2W=`./ptarmcli --paytowallet ${TARGET_NODE}`
echo ${P2W} | jq .
AMOUNT=`echo ${P2W} | jq -r -e '.result.wallet.amount'`
if [ ${AMOUNT} -eq 0 ]; then
    echo ERROR: amount == 0
    exit 1
fi
LIST=`echo ${P2W} | jq -r -e '.result.list | length'`
if [ ${LIST} -ne 1 ]; then
    echo ERROR: list.len != 1
    exit 1
fi
echo ---------- OK: HTLC_tx conf=31 ---------------

echo ---------- spend: HTLC_tx ---------------
P2W=`./ptarmcli --paytowallet=1 ${TARGET_NODE}`
echo ${P2W} | jq .
AMOUNT=`echo ${P2W} | jq -r -e '.result.wallet.amount'`
if [ ${AMOUNT} -eq 0 ]; then
    echo ERROR: amount == 0
    exit 1
fi
LIST=`echo ${P2W} | jq -r -e '.result.list | length'`
if [ ${LIST} -ne 1 ]; then
    echo ERROR: list.len != 1
    exit 1
fi
echo ---------- OK: spend: HTLC_tx ---------------

echo ---------- after spend: HTLC_tx ---------------
P2W=`./ptarmcli --paytowallet ${TARGET_NODE}`
echo ${P2W} | jq .
AMOUNT=`echo ${P2W} | jq -r -e '.result.wallet.amount'`
if [ ${AMOUNT} -ne 0 ]; then
    echo ERROR: amount != 0
    exit 1
fi
LIST=`echo ${P2W} | jq -r -e '.result.list | length'`
if [ ${LIST} -ne 0 ]; then
    echo ERROR: list.len != 0
    exit 1
fi
echo ---------- OK: after spend: HTLC_tx ---------------

blockcount=`getblockcount`
if [ $blockcount -ne $((BASECOUNT+32) ]; then
    echo blockcount is not +32\($blockcount\)
    exit 1
fi
