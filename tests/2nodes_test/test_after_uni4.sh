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
    if [ $# -eq 1 ] && [ "$1" = "same" ]; then
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


# 1: amount require type(SAME, DIFF)
# 2: amount require value
# 3: list require type(SAME, DIFF)
# 4: list require items
check_paytowallet() {
    ./ptarmcli --getinfo ${TARGET_NODE}

    P2W=`./ptarmcli --paytowallet ${TARGET_NODE}`
    echo ${P2W} | jq .
    AMOUNT=`echo ${P2W} | jq -r -e '.result.wallet.amount'`
    LIST=`echo ${P2W} | jq -r -e '.result.list | length'`

    ret=0
    if [ "$1" = "SAME" ]; then
        if [ ${AMOUNT} -eq $2 ]; then
            echo OK: amount == $2
        else
            echo ERROR: amount != $2
            ret=1
        fi
    else
        if [ ${AMOUNT} -ne $2 ]; then
            echo OK: amount != $2
        else
            echo ERROR: amount == $2
            ret=1
        fi
    fi
    if [ "$3" = "SAME" ]; then
        if [ ${LIST} -eq $4 ]; then
            echo OK: list == $4
        else
            echo ERROR: list != $4
            ret=1
        fi
    else
        if [ ${LIST} -ne $4 ]; then
            echo OK: list != $4
        else
            echo ERROR: list == $4
            ret=1
        fi
    fi
    return ${ret}
}


echo node_3333 no-fulfill return
./ptarmcli --debug 1 3334

echo st4e start
./example_st4e.sh
sleep 5 # XXX: TODO
check_amount
echo st4e end

TARGET_NODE=3334

CLOSE_PUBKEY=`./showdb -d node_3333 -s | jq -r .channel_info[0].close.local_scriptPubKey`
echo CLOSE_PUBKEY=${CLOSE_PUBKEY}

BASECOUNT=`getblockcount`
echo BASECOUNT=${BASECOUNT}

echo unilateral close from 4444
./ptarmcli -c conf/peer3333.conf -xforce 4445

echo quit 4444
./ptarmcli -q 4445
sleep 3

echo 4444がoffered HTLC、3333がreceived HTLCを持った状態。
echo unilateral closeを4444が行い、3333を確認していく\(local unilateral close\)。4444はkill済み。
echo    to_self_delay: node_3333=30, node_4444=31
echo
echo まず、to_remote outputはすぐに使用可能。
echo 次のgenerateでcommit_txがminingされるが、preimageを持っているので取り戻す。

# (alpha=438)
# blockcount: alpha
#       remote commit_tx broadcast
# blockcount: alpha+1 *A
#       commit_tx conf=1
#       to_remote output ==> spendable
#       offered HTLC ==> auto spend to 1st layer wallet
# blockcount: alpha+2 *B
#       commit_tx conf=2

# *A
#   remote commit_tx=1conf
#   to_remote:
#       paytowallet可能
#   offered HTLC:
#       preimage持ちなので自動送金。
./generate.sh 1
sleep 30
echo ---------- commit_tx conf=1 ---------------
check_paytowallet DIFF 0 SAME 1
if [ $? -ne 0 ]; then
    exit 1
fi
echo ---------- OK: commit_tx conf=1 ---------------

#   to_remote:
#       paytowallet対象
echo ---------- spend: to_remote output ---------------
P2W=`./ptarmcli --paytowallet=1 ${TARGET_NODE}`
echo ${P2W} | jq .
echo ---------- OK: spend: to_remote output ---------------

#   残なし
echo ---------- after spend: to_remote output ---------------
check_paytowallet SAME 0 SAME 0
if [ $? -ne 0 ]; then
    exit 1
fi
echo ---------- OK: after spend: to_remote output ---------------

blockcount=`getblockcount`
if [ $blockcount -ne $((BASECOUNT+1)) ]; then
    echo blockcount is not +1\($blockcount\)
    exit 1
fi

# bitcoind版のみ
if [ "$1" = "BITCOIND" ]; then
    echo ---------- after spend: HTLC ---------------
    ./generate.sh 1
    echo BITCOIND check
    CNT=`bitcoin-cli -datadir=. -conf=regtest.conf listunspent | grep -c ${CLOSE_PUBKEY}`
    if [ ${CNT} -ne 1 ]; then
        echo HTLC not spend
        exit 1
    fi
    echo ---------- OK: after spend: HTLC ---------------
fi

if [ "$1" = "BITCOIND" ]; then
    # 1BTCより大きいものはminingだろうから、それより小さいものだけ出力
    CNT=`bitcoin-cli -datadir=. -conf=regtest.conf listunspent | jq -e '. | map(select(.amount < 1)) | length'`
    if [ ${CNT} -eq 2 ]; then
        echo unspent == 2\(to_remote and HTLC\)
    else
        echo ERROR: unspent != 2
        exit 1
    fi
fi
