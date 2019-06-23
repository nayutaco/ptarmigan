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

TARGET_NODE=4445

CLOSE_PUBKEY=`./showdb -d node_4444 -s | jq -r .channel_info[0].close.local_scriptPubKey`
echo CLOSE_PUBKEY=${CLOSE_PUBKEY}

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
# blockcount: alpha+1 *A
#       commit_tx conf=1
# ...
#
# blockcount: alpha+19 *B
#       commit_tx conf=19
#       offered HTLC ==> HTLC Timeout tx broadcast
# blockcount: alpha+20 *C
#       commit_tx conf=20
#       HTLC_tx conf=1
#
# ...
#
# blockcount: alpha+30 *D
#       commit_tx conf=30 ==> spendable
#       HTLC_tx conf=11
#
# ...
#
# blockcount: alpha+49 *E
#       HTLC_tx conf=30 ==> spendable

# *A
#   local commit_tx=1conf
#   to_local:
#       to_self_delay待ち
#   offered HTLC:
#       cltv_expiry待ちだが表に出てこない
./generate.sh 1
sleep 30
echo ---------- commit_tx conf=1 ---------------
check_paytowallet SAME 0 SAME 1
if [ $? -ne 0 ]; then
    exit 1
fi
echo ---------- OK: commit_tx conf=1 ---------------

# *B
#   local commit_tx=19conf
#   to_local:
#       to_self_delay待ち
#   offered HTLC:
#       cltv_expiry経過によりHTLC Timeout tx展開し、to_self_delay待ち
#       bitcoindはすぐにSPENTを検出するためリストに出てくる。
./generate.sh 18
sleep 30
echo ---------- commit_tx conf=19, HTLC_tx conf=0 ---------------
if [ "$1" = "BITCOIND" ]; then
    check_paytowallet SAME 0 SAME 2
    if [ $? -eq 0 ]; then
        echo OK if bitcoind version
    else
        exit 1
    fi
elif [ "$1" = "BITCOINJ" ]; then
    check_paytowallet SAME 0 SAME 1
    if [ $? -eq 0 ]; then
        echo OK if bitcoinj version
    else
        exit 1
    fi
else
    echo ERROR
    exit 1
fi
echo ---------- OK: commit_tx conf=19, HTLC_tx conf=0 ---------------

# *C
#   local commit_tx=20conf
#   to_local:
#       to_self_delay待ち
#   HTLC Timeout tx:
#       to_self_delay待ち
#       bitcoinjもSPENTを検出できるようになるはずだが、そうもいかないことがある。
./generate.sh 1
sleep 30
echo ---------- commit_tx conf=20, HTLC_tx conf=1 ---------------
check_paytowallet SAME 0 SAME 2
if [ $? -ne 0 ]; then
    exit 1
fi
echo ---------- OK: commit_tx conf=20, HTLC_tx conf=1 ---------------

# *C
#   local commit_tx=30conf
#   to_local:
#       to_self_delay経過によりpaytowallet可能
#   HTLC Timeout tx:
#       to_self_delay待ち
./generate.sh 10
sleep 30
echo ---------- commit_tx conf=30, HTLC_tx conf=11 ---------------
check_paytowallet DIFF 0 SAME 2
if [ $? -ne 0 ]; then
    exit 1
fi
echo ---------- OK: commit_tx conf=40, HTLC_tx conf=21 ---------------

#   to_local:
#       paytowallet対象
#   HTLC Timeout tx:
#       paytowallet対象外
echo ---------- spend: to_local output ---------------
P2W=`./ptarmcli --paytowallet=1 ${TARGET_NODE}`
echo ${P2W} | jq .
echo ---------- OK: spend: to_local output ---------------

#   HTLC Timeout tx:
#       paytowallet対象外
echo ---------- after spend: to_local output ---------------
check_paytowallet SAME 0 SAME 1
if [ $? -ne 0 ]; then
    exit 1
fi
echo ---------- OK: after spend: to_local output ---------------

#   local commit_tx=48conf
#   HTLC Timeout tx:
#       to_self_delay待ち
./generate.sh 18
sleep 30
echo ---------- HTLC_tx conf=29 ---------------
check_paytowallet SAME 0 SAME 1
if [ $? -ne 0 ]; then
    exit 1
fi
echo ---------- OK: HTLC_tx conf=29 ---------------

# *E
#   local commit_tx=49conf
#   HTLC Timeout tx:
#       to_self_delay経過によりpaytowallet可能
./generate.sh 1
sleep 30
echo ---------- HTLC_tx conf=30 ---------------
check_paytowallet DIFF 0 SAME 1
if [ $? -ne 0 ]; then
    exit 1
fi
echo ---------- OK: HTLC_tx conf=30 ---------------

#   HTLC Timeout tx:
#       paytowallet対象
echo ---------- spend: HTLC_tx ---------------
P2W=`./ptarmcli --paytowallet=1 ${TARGET_NODE}`
echo ${P2W} | jq .
echo ---------- OK: spend: HTLC_tx ---------------

#   残なし
echo ---------- after spend: HTLC_tx ---------------
check_paytowallet SAME 0 SAME 0
if [ $? -ne 0 ]; then
    exit 1
fi
echo ---------- OK: after spend: HTLC_tx ---------------

blockcount=`getblockcount`
if [ $blockcount -ne $((BASECOUNT+49)) ]; then
    echo blockcount is not +49\($blockcount\)
    exit 1
fi

echo 最後の送金をマイニングして確定させる。
echo bitcoindならlistunspentで2つ見えるはず。
./generate.sh 1

if [ "$1" = "BITCOIND" ]; then
    # 1BTCより大きいものはminingだろうから、それより小さいものだけ出力
    CNT=`bitcoin-cli -datadir=. -conf=regtest.conf listunspent | jq -e '. | map(select(.amount < 1)) | length'`
    if [ ${CNT} -eq 2 ]; then
        echo unspent == 2\(to_local and HTLC\)
    else
        echo ERROR: unspent != 2
        exit 1
    fi
fi
