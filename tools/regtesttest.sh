#!/bin/bash

# aaaa: 12345 : fundee
# bbbb: 23456 : funder

BASENAME=`basename $PWD`
if [ ${BASENAME} != "install" ]; then
	echo "execute in install/."
	exit 1
fi

CLI="bitcoin-cli"

CHAIN=`${CLI} getblockchaininfo | jq -r -e '.chain'`
if [ "${CHAIN}" != "regtest" ]; then
    echo "not regtest"
    exit 1
fi

BLOCK=`${CLI} getblockcount`
if [ ${BLOCK} -lt 500 ]; then
    ${CLI} generate 500
    sleep 5
fi
${CLI} sendtoaddress `${CLI} getnewaddress` 0.1
${CLI} generate 1

sleep 5

rm -rf aaaa bbbb
./new_nodedir.sh aaaa
./new_nodedir.sh bbbb

cd aaaa
../ptarmd --network=regtest --port=12345&
cd ../bbbb
../ptarmd --network=regtest --port=23456&
cd ..

sleep 2

NODE1=`./ptarmcli --getinfo 12346 | jq -r -e '.result.node_id'`
NODE2=`./ptarmcli --getinfo 23457 | jq -r -e '.result.node_id'`
echo NODE1=${NODE1}
echo NODE2=${NODE2}

./ptarmcli -c ${NODE1}@127.0.0.1:12345 23457

sleep 1

./ptarmcli -c ${NODE1} -f 500000 23457

sleep 1

${CLI} generate 1

while :
do
    STAT1=`./ptarmcli -l 12346 | jq -r -e '.result.peers[0].status'`
    STAT2=`./ptarmcli -l 23457 | jq -r -e '.result.peers[0].status'`
    echo STAT1=$STAT1 STAT2=$STAT2
    if [ "$STAT1" == "normal operation" ] && [ "$STAT2" == "normal operation" ]; then
        break
    fi
    sleep 3
done
echo OK - funding

CHAN1=`./ptarmcli --getinfo 12346 | jq -r -e '.result.peers[0].channel_id'`
echo ${CHAN1}
echo ${#CHAN1}
CHAN2=`./ptarmcli --getinfo 23457 | jq -r -e '.result.peers[0].channel_id'`
echo ${CHAN2}
echo ${#CHAN2}
if [ ${#CHAN1} -ne 64 ] || [ ${#CHAN2} -ne 64 ] || [ ${CHAN1} != ${CHAN2} ]; then
	echo "channel_id not same"
	echo "  chan1=${CHAN1}"
	echo "  chan2=${CHAN2}"
	exit 1
fi

echo --------------------------------------

INVOICE=`./ptarmcli --createinvoice=2000000 12346 | jq -r -e '.result.bolt11'`
echo invoice=${INVOICE}
./ptarmcli --sendpayment=${INVOICE} 23457

while :
do
    LOCAL1=`./ptarmcli --getinfo 12346 | jq -e '.result.peers[0].local.msatoshi'`
    LOCAL2=`./ptarmcli --getinfo 23457 | jq -e '.result.peers[0].local.msatoshi'`
    echo LOCAL1=$LOCAL1 LOCAL2=$LOCAL2
    if [ "$LOCAL1" -eq 2000000 ] && [ "$LOCAL2" -eq 498000000 ]; then
        break
    fi
    sleep 3
done
echo OK - 1

echo --------------------------------------

INVOICE=`./ptarmcli --createinvoice=1000 23457 | jq -r -e '.result.bolt11'`
echo invoice=${INVOICE}
./ptarmcli --sendpayment=${INVOICE} 12346

while :
do
    LOCAL1=`./ptarmcli --getinfo 12346 | jq -e '.result.peers[0].local.msatoshi'`
    LOCAL2=`./ptarmcli --getinfo 23457 | jq -e '.result.peers[0].local.msatoshi'`
    echo LOCAL1=$LOCAL1 LOCAL2=$LOCAL2
    if [ "$LOCAL1" -eq 1999000 ] && [ "$LOCAL2" -eq 498001000 ]; then
        break
    fi
    sleep 3
done
echo OK - 2

echo --------------------------------------

./ptarmcli -c ${NODE1} -x 23457

sleep 3
${CLI} generate 1

while :
do
    LOCAL1=`./ptarmcli --getinfo 12346 | jq -e '.result.peers | length'`
    LOCAL2=`./ptarmcli --getinfo 23457 | jq -e '.result.peers | length'`
    echo LOCAL1=$LOCAL1 LOCAL2=$LOCAL2
    if [ "$LOCAL1" -eq 0 ] && [ "$LOCAL2" -eq 0 ]; then
        break
    fi
    sleep 3
done
echo closed

echo --------------------------------------

CLOSED1=`./showdb --datadir=aaaa --listclosed | jq -r -e '.[0]'`
CLOSED2=`./showdb --datadir=bbbb --listclosed | jq -r -e '.[0]'`
if [ ${CLOSED1} != ${CLOSED2} ] || [ ${CLOSED1} != ${CHAN2} ]; then
	echo "invalid closed channel"
	echo "   close1=${CLOSED1}"
	echo "   close2=${CLOSED2}"
	exit 1
fi


echo --------------------------------------

./ptarmcli -q 12346
./ptarmcli -q 23457

sleep 3

rm -rf aaaa bbbb

echo --------------------------------------

# while :
# do
#     CHN1=`./showdb -c -d aaaa | jq '.[]|length'`
#     CHN2=`./showdb -c -d bbbb | jq '.[]|length'`
#     NOD1=`./showdb -n -d aaaa | jq '.[]|length'`
#     NOD2=`./showdb -n -d bbbb | jq '.[]|length'`
#     echo CHAN1=$CHN1:$NOD1 CHAN2=$CHN2:$NOD2
#     if [ "$CHN1" -eq 2 ] && [ "$CHN2" -eq 2 ] && [ "$NOD1" -eq 2 ] && [ "$NOD2" -eq 2 ]; then
#         break
#     fi
#     sleep 3
# done

