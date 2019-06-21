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
