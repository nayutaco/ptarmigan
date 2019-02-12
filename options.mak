# 0:mainnet, 1:testnet
NETKIND=1

# node type
#    BITCOIND, BITCOINJ
NODE_TYPE=BITCOIND

JDK_COMPILE=x86_64
#JDK_COMPILE=RASPI
#JDK_COMPILE=RASPI_ARM11

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

# gcc prefix
#GNU_PREFIX := arm-linux-gnueabihf-


######################################
#common
######################################

CFLAGS += -DNETKIND=$(NETKIND)

ifeq ($(NODE_TYPE),BITCOIND)
CFLAGS += -DUSE_BITCOIND
NODESET=1
endif
ifeq ($(NODE_TYPE),BITCOINJ)
CFLAGS += -DUSE_BITCOINJ
NODESET=1
ifeq ($(JDK_COMPILE),x86_64)
    #JDK for x86_64
    JDK_HOME := /usr/lib/jvm/java-8-openjdk-amd64
    JDK_CPU := amd64/server
endif
ifeq ($(JDK_COMPILE),RASPI)
    #JDK for oracle-java8-jdk (Raspberry-Pi 2/3)
    JDK_HOME := /usr/lib/jvm/jdk-8-oracle-arm32-vfp-hflt
    JDK_CPU := arm/server
endif
ifeq ($(JDK_COMPILE),RASPI_ARM11)
    #JDK for openjdk-8-jdk (Raspberry-Pi 1/Zero)
    JDK_HOME := /usr/lib/jvm/java-8-openjdk-armhf
    JDK_CPU := arm/client
endif
ifeq ($(JDK_HOME),)
    $(error You must set JDK_COMPILE in options.mak.)
endif
SPV_JAR_PATH = $(JDK_HOME)/jre/lib/$(JDK_CPU)
USE_SPV_JVM = -L$(SPV_JAR_PATH)
JVM_PATH = $(SPV_JAR_PATH)/libjvm.so
JAR_EXISTS = $(shell ls $(JVM_PATH) | grep $(JVM_PATH))
#$(info $(JVM_PATH))
#$(info $(JAR_EXISTS))
ifneq ($(JAR_EXISTS),$(JVM_PATH))
    $(error  libjvm.so not found.)
endif
endif

ifneq ($(NODESET),1)
    $(error You must set correct NODE_TYPE in options.mak.)
endif

ifeq ($(DISABLE_PRINTFUND),0)
	CFLAGS += -DPTARM_USE_PRINTFUNC
endif


ifeq ($(ENABLE_COVERAGE),1)
	CFLAGS += --coverage
	LDFLAGS += --coverage
endif


ifeq ($(ENABLE_DEVELOPER_MODE),1)
	CFLAGS += -DDEVELOPER_MODE
endif


# for syscall()
CFLAGS += -D_GNU_SOURCE
