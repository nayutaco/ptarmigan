#!/bin/sh

TARGET=x86_64
#TARGET=RASPI
#TARGET=RASPI_ARM11

if [ "$TARGET" = "x86_64" ]; then
#JDK for x86_64
export JDK_HOME=/usr/lib/jvm/java-8-openjdk-amd64
export JDK_CPU=amd64/server
echo $TARGET

elif [ "$TARGET" = "RASPI" ]; then
#JDK for Raspberry-Pi 2/3
export JDK_HOME=/usr/lib/jvm/jdk-8-oracle-arm32-vfp-hflt
export JDK_CPU=arm/server
echo $TARGET

elif [ "$TARGET" = "RASPI_ARM11" ]; then
#JDK for Raspberry-Pi 1/Zero
export JDK_HOME=/usr/lib/jvm/java-8-openjdk-armhf
export JDK_CPU=arm/client
echo $TARGET

else
echo You MUST set TARGET.
return
fi

export LD_LIBRARY_PATH=$JDK_HOME/jre/lib/$JDK_CPU
ls -l $LD_LIBRARY_PATH/libjvm.so
