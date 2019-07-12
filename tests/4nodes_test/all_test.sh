#!/bin/bash -ue

SLEEP_SEC=6

msat3=0
msat4=0
msat5=0
msat6=0

amount() {
    echo `./ptarmcli -l $1 | jq -e '.result.total_local_msat'`
}

get_amount() {
    msat3=`amount 3334`
    msat4=`amount 4445`
    msat5=`amount 5556`
    msat6=`amount 6667`
    echo msat3=${msat3} msat4=${msat4} msat5=${msat5} msat6=${msat6}
}

check_amount() {
    echo check amount start
    msat3_after=`amount 3334`
    msat4_after=`amount 4445`
    msat5_after=`amount 5556`
    msat6_after=`amount 6667`
    echo msat3=${msat3_after} msat4=${msat4_after} msat5=${msat5_after} msat6=${msat6_after}
    if [ $# -eq 1 ] && [ "$1" = "same" ]; then
        if [ ${msat3} -ne ${msat3_after} ]; then
            echo invalid amount3: != ${msat3}
            exit 1
        fi
        if [ ${msat4} -ne ${msat4_after} ]; then
            echo invalid amount4: != ${msat4}
            exit 1
        fi
        if [ ${msat5} -ne ${msat5_after} ]; then
            echo invalid amount5: != ${msat5}
            exit 1
        fi
        if [ ${msat6} -ne ${msat6_after} ]; then
            echo invalid amount6: != ${msat6}
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
        if [ ${msat5} -eq ${msat5_after} ]; then
            echo invalid amount5: == ${msat5}
            exit 1
        fi
        if [ ${msat6} -eq ${msat6_after} ]; then
            echo invalid amount6: == ${msat6}
            exit 1
        fi
    fi
    msat3=${msat3_after}
    msat4=${msat4_after}
    msat5=${msat5_after}
    msat6=${msat6_after}
    echo check amount end
}

function check_live() {
	echo check proc count start
	PROC_COUNT=`ps -C ptarmd | grep ptarmd | wc -l`
	test $PROC_COUNT == 4
	echo check proc count end
}

function check_log() {
    echo check log
    BAD_LINE_COUNT=`./log_filter.sh | wc -l`
    if [ $BAD_LINE_COUNT -ne 0 ];
    then
        ./log_filter.sh
        exit 1
    fi
    echo check log end
}

START=`date +%s`

echo clean start
./clean.sh >/dev/null 2>&1 | :
echo clean end

echo st1 start
./example_st1.sh
echo st1 end

echo st2 start
./example_st2.sh
sleep 5 # wait conf file
echo st2 end

echo st3 start
./example_st3.sh
sleep ${SLEEP_SEC} # XXX: TODO
echo st3 end

check_live
check_log
get_amount

echo st4c start
./example_st4c.sh
sleep ${SLEEP_SEC} # XXX: TODO
echo st4c end

check_live
check_log
check_amount

FEERATE_PER_KW=600
echo update_fee $FEERATE_PER_KW start
./example_st_update_fee_all.sh $FEERATE_PER_KW
sleep ${SLEEP_SEC} # XXX: TODO
echo update_fee $FEERATE_PER_KW end

check_live
check_log
check_amount same

echo st4d start
./example_st4d.sh
sleep ${SLEEP_SEC} # XXX: TODO
echo st4d end

check_live
check_log
check_amount

echo st4e start
./example_st4e.sh
sleep ${SLEEP_SEC} # XXX: TODO
echo st4e end

check_live
check_log
check_amount

echo st4f start
./example_st4f.sh
sleep ${SLEEP_SEC} # XXX: TODO
echo st4f end

check_live
check_log
check_amount

echo disconnect start
./example_st_quit.sh
sleep 5
echo disconnect end

echo clear skip route
for i in 3333 4444 5555 6666
do
    ./routing -d ./node_$i -c
done

echo reconnect start
./example_st_conn.sh
sleep 5
echo reconnect end

check_live
check_log
check_amount same

echo st4c start
./example_st4c.sh
sleep ${SLEEP_SEC} # XXX: TODO
echo st4c end

check_live
check_log
check_amount

echo st4d start
./example_st4d.sh
sleep ${SLEEP_SEC} # XXX: TODO
echo st4d end

check_live
check_log
check_amount

FEERATE_PER_KW=700
echo update_fee $FEERATE_PER_KW start
./example_st_update_fee_all.sh $FEERATE_PER_KW
sleep ${SLEEP_SEC} # XXX: TODO
echo update_fee $FEERATE_PER_KW end

check_live
check_log
check_amount same

echo st4e start
./example_st4e.sh
sleep ${SLEEP_SEC} # XXX: TODO
echo st4e end

check_live
check_log
check_amount

echo st4f start
./example_st4f.sh
sleep ${SLEEP_SEC} # XXX: TODO
echo st4f end

check_live
check_log
check_amount

echo st5 start
./example_st5.sh
sleep ${SLEEP_SEC} # XXX: TODO
echo st5 end

check_live
check_log

if [ $# -eq 1 ] && [ $1 = "stop" ]; then
    exit 0
fi

echo clean start
./clean.sh
echo clean end

END=`date +%s`
ELAPSED=`expr $END - $START` 
echo "$ELAPSED seconds"
