#!/bin/sh
sed -i 's/NODE_TYPE=BITCOIND/NODE_TYPE=BITCOINJ/g' options.mak
sed -i 's/JDK_COMPILE=x86_64/#JDK_COMPILE=x86_64/g' options.mak
sed -i 's/#JDK_COMPILE=RASPI_ARM11/JDK_COMPILE=RASPI_ARM11/g' options.mak
sed -i 's/TARGET=x86_64/#TARGET=x86_64/g' install/jdk.sh
sed -i 's/#TARGET=RASPI_ARM11/TARGET=RASPI_ARM11/g' install/jdk.sh

