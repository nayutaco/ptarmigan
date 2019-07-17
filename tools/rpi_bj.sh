#!/bin/sh
sed -i 's/NODE_TYPE=BITCOIND/NODE_TYPE=BITCOINJ/g' options.mak
sed -i 's/JDK_COMPILE=x86_64/#JDK_COMPILE=x86_64/g' options.mak
sed -i 's/#JDK_COMPILE=ARM_RASPI/JDK_COMPILE=ARM_RASPI/g' options.mak
sed -i 's/USE_OPENSSL=0/USE_OPENSSL=1/g' options.mak
sed -i 's/DISABLE_PRINTFUND=0/DISABLE_PRINTFUND=1/g' options.mak

sed -i 's/TARGET=x86_64/#TARGET=x86_64/g' install/jdk.sh
sed -i 's/#TARGET=ARM_RASPI/TARGET=ARM_RASPI/g' install/jdk.sh
