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

source ../../install/jdk.sh
JVM=`ls -l $LD_LIBRARY_PATH/libjvm.so | grep -c libjvm.so`
if [ ${JVM} -eq 0 ]; then
    echo no JVM
    exit 1
fi


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
./example_st3j.sh
if [ $? -ne 0 ]; then
    exit 1
fi
sleep 5 # XXX: TODO
echo st3 end

get_amount
if [ ${msat3} -ne 300000000 ]; then
    echo invalid amount3: ${msat3}
    exit 1
fi
if [ ${msat4} -ne 300000000 ]; then
    echo invalid amount4: ${msat4}
    exit 1
fi

echo st4c start
./example_st4c.sh
sleep 5 # XXX: TODO
check_amount
echo st4c end

echo st4d start
./example_st4d.sh
sleep 5 # XXX: TODO
check_amount
echo st4d end

echo st4e start
./example_st4e.sh
sleep 5 # XXX: TODO
check_amount
echo st4e end

echo st4f start
./example_st4f.sh
sleep 5 # XXX: TODO
check_amount
echo st4f end

echo disconnect start
./example_st_quit.sh
sleep 5
echo disconnect end

echo clear skip route
for i in 3333 4444
do
   ./routing -d ./node_$i -c
done

echo reconnect start
./example_st_conn.sh
sleep 5
check_amount same
echo reconnect end

echo st4c start
./example_st4c.sh
sleep 5 # XXX: TODO
check_amount
echo st4c end

echo st4d start
./example_st4d.sh
sleep 5 # XXX: TODO
check_amount
echo st4d end

echo st4e start
./example_st4e.sh
sleep 5 # XXX: TODO
check_amount
echo st4e end

echo st4f start
./example_st4f.sh
sleep 5 # XXX: TODO
check_amount
echo st4f end

echo st5 start
./example_st5.sh
sleep 5 # XXX: TODO
echo st5 end

if [ $# -eq 1 ] && [ $1 == "stop" ]; then
    exit 0
fi

echo clean start
./clean.sh
echo clean end

END=`date +%s`
ELAPSED=`expr $END - $START` 
echo "$ELAPSED seconds"
