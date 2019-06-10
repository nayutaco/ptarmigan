#!/bin/sh

TARGET=x86_64
#TARGET=RASPI_ARM11

if [ "$TARGET" = "x86_64" ]; then
#JDK for x86_64
export JDK_HOME=/usr/lib/jvm/java-8-openjdk-amd64
export JDK_CPU=amd64/server
echo $TARGET

elif [ "$TARGET" = "ARM_RASPI" ]; then
#JDK for openjdk-8-jdk (Raspberry-Pi)
export JDK_HOME=/usr/lib/jvm/java-8-openjdk-armhf
export JDK_CPU=arm/client
echo $TARGET

else
echo You MUST set TARGET.
return
fi

export LD_LIBRARY_PATH=$JDK_HOME/jre/lib/$JDK_CPU
ls -l $LD_LIBRARY_PATH/libjvm.so
