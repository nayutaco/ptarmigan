#!/bin/sh

#JDK for x86_64
export JDK_HOME=/usr/lib/jvm/java-8-openjdk-amd64
export JDK_CPU=amd64

#JDK for Raspberry-Pi
#export JDK_HOME=/usr/lib/jvm/jdk-8-oracle-arm32-vfp-hflt
#export JDK_CPU=arm

export LD_LIBRARY_PATH=$JDK_HOME/jre/lib/$JDK_CPU/server
