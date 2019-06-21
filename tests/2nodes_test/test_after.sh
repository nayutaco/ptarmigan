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
check_amount
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
