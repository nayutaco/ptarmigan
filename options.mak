#GNU_PREFIX := arm-linux-gnueabihf-

#JDK for x86_64
JDK_HOME := /usr/lib/jvm/java-8-openjdk-amd64
JDK_CPU := amd64

#JDK for Raspberry-Pi
#JDK_HOME := /usr/lib/jvm/jdk-8-oracle-arm32-vfp-hflt
#JDK_CPU := arm

# 0:mainnet, 1:testnet
NETKIND=1

# 0:not SPV 1:SPV
USE_SPV=0
USE_SPV_JVM = -L$(JDK_HOME)/jre/lib/$(JDK_CPU)/server

# build ptarmd(WARNING: if you change this setting, need rebuild)
#   EXEC
#     as process
#   LIB
#     as library
BUILD_PTARMD=EXEC
BUILD_PTARMD_LIB_INCPATHS = -I$(JDK_HOME)/include -I$(JDK_HOME)/include/linux

# 0: enable print func 1:disable
#  priority higher than PTARM_USE_PRINTFUNC
DISABLE_PRINTFUND=0

# 0: disable gcov 1:enable
ENABLE_COVERAGE=0

# 0: disable developer mode 1:enable
ENABLE_DEVELOPER_MODE=0

# 0: log to file 1: stdout
ENABLE_PLOG_TO_STDOUT_PTARMD=0

# max channels("conntct to"(MAX_CHANNELS) and "conect from"(MAX_CHANNELS))
MAX_CHANNELS=10
