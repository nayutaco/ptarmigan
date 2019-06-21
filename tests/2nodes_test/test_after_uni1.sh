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

TARGET_NODE=4445

echo quit 3333
./ptarmcli -q 3334
sleep 3

BASECOUNT=`getblockcount`
echo BASECOUNT=${BASECOUNT}

echo unilateral close from 4444
./ptarmcli -c conf/peer3333.conf -xforce ${TARGET_NODE}

echo 4444がoffered HTLC、3333がreceived HTLCを持った状態。
echo unilateral closeを4444が行い、4444を確認していく\(local unilateral close\)。3333はkill済み。
echo    to_self_delay: node_3333=30, node_4444=31
echo
echo デフォルトではinvoiceのmin_final_cltv_expiryは9で、オフセットも含めると19になっている。
echo 次のgenerateでcommit_txがminingされ、さらに18generateするとHTLC Timeout Txを展開。
echo spending to_local output txは、to_self_delayが30なので、commit_txが30confでspendableになる。
echo HTLC Timeout Txが30confになるとspendableになる。

# (alpha=438)
# blockcount: alpha
#       local commit_tx broadcast
# blockcount: alpha+1
#       commit_tx conf=1
# ...
#
# blockcount: alpha+19
#       commit_tx conf=19
#       offered HTLC ==> HTLC Timeout tx broadcast
# blockcount: alpha+20
#       commit_tx conf=20
#       HTLC_tx conf=1
#
# ...
#
# blockcount: alpha+30
#       commit_tx conf=30 ==> spendable
#       HTLC_tx conf=11
#
# ...
#
# blockcount: alpha+49
#       HTLC_tx conf=30 ==> spendable

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
if [ ${LIST} -ne 1 ]; then
    echo ERROR: list.len != 1
    exit 1
fi
echo ---------- OK: commit_tx conf=1 ---------------

./generate.sh 18
sleep 30
echo ---------- commit_tx conf=19, HTLC_tx conf=0 ---------------
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
echo ---------- OK: commit_tx conf=19, HTLC_tx conf=0 ---------------

./generate.sh 1
sleep 30
echo ---------- commit_tx conf=20, HTLC_tx conf=1 ---------------
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
echo ---------- OK: commit_tx conf=20, HTLC_tx conf=1 ---------------

./generate.sh 10
sleep 30
echo ---------- commit_tx conf=30, HTLC_tx conf=11 ---------------
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
echo ---------- OK: commit_tx conf=40, HTLC_tx conf=21 ---------------

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

./generate.sh 18
sleep 30
echo ---------- HTLC_tx conf=29 ---------------
./ptarmcli --getinfo ${TARGET_NODE}
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
echo ---------- OK: HTLC_tx conf=29 ---------------

./generate.sh 1
sleep 30
echo ---------- HTLC_tx conf=30 ---------------
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
echo ---------- OK: HTLC_tx conf=30 ---------------

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
if [ $blockcount -ne $((BASECOUNT+49)) ]; then
    echo blockcount is not +49\($blockcount\)
    exit 1
fi
