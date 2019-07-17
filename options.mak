# node type
#    BITCOIND, BITCOINJ
NODE_TYPE=BITCOIND

JDK_COMPILE=x86_64
#JDK_COMPILE=ARM_RASPI

# build ptarmd(WARNING: if you change this setting, need rebuild)
#   EXEC
#     as process
#   LIB
#     as library
BUILD_PTARMD=EXEC
BUILD_PTARMD_LIB_INCPATHS = -I$(JDK_HOME)/include -I$(JDK_HOME)/include/linux

# use OpenSSL library
#   apt install libssl-dev
USE_OPENSSL=0

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

$(info -----------------------------)
$(info options.mak)

ifeq ($(NODE_TYPE),BITCOIND)
    $(info - bitcoind version)
    CFLAGS += -DUSE_BITCOIND
    NODESET=1
endif
ifeq ($(NODE_TYPE),BITCOINJ)
    CFLAGS += -DUSE_BITCOINJ
    NODESET=1
    ifneq ($(strip $(GNU_PREFIX)),)
        #use own jvm
        $(info - cross compile SPV version)
        JDK_HOME := $(dir $(lastword $(MAKEFILE_LIST)))/libs
        JDK_X86_HOME := /usr/lib/jvm/java-8-openjdk-amd64
        JDK_CPU := client
        BUILD_PTARMD_LIB_INCPATHS += -I$(JDK_X86_HOME)/include -I$(JDK_X86_HOME)/include/linux
    else ifeq ($(shell uname -p)$(NODE_TYPE)$(JDK_COMPILE),x86_64BITCOINJARM_RASPI)
        #cross compile and use own jvm
        $(info - SPV version for ARM automatic)
        GNU_PREFIX := arm-linux-gnueabihf-
        JDK_HOME := $(dir $(lastword $(MAKEFILE_LIST)))/libs
        JDK_X86_HOME := /usr/lib/jvm/java-8-openjdk-amd64
        JDK_CPU := client
        BUILD_PTARMD_LIB_INCPATHS += -I$(JDK_X86_HOME)/include -I$(JDK_X86_HOME)/include/linux
    else ifeq ($(JDK_COMPILE),x86_64)
        $(info - SPV version for x86_64)
        #JDK for x86_64
        JDK_HOME := /usr/lib/jvm/java-8-openjdk-amd64
        JDK_CPU := amd64/server
    else ifeq ($(JDK_COMPILE),ARM_RASPI)
        $(info - SPV version for ARM)
        #JDK for openjdk-8-jdk (Raspberry-Pi)
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
    ifneq ($(JAR_EXISTS),$(JVM_PATH))
        $(info JVM_PATH=$(JVM_PATH))
        $(info JAR_EXISTS=$(JAR_EXISTS))
        $(error  libjvm.so not found.)
    endif
endif

ifneq ($(NODESET),1)
    $(error You must set correct NODE_TYPE in options.mak.)
endif

ifeq ($(DISABLE_PRINTFUND),0)
    $(info - PTARM_USE_PRINTFUNC)
	CFLAGS += -DPTARM_USE_PRINTFUNC
endif


ifeq ($(ENABLE_COVERAGE),1)
    $(info - COVERAGE)
	CFLAGS += --coverage
	LDFLAGS += --coverage
endif


ifeq ($(ENABLE_DEVELOPER_MODE),1)
    $(info - DEVELOPER MODE)
	CFLAGS += -DDEVELOPER_MODE
endif

ifeq ($(ENABLE_PLOG_TO_STDOUT_PTARMD),1)
    $(info - ENABLE_PLOG_TO_STDOUT_PTARMD)
endif

$(info - MAX_CHANNELS=$(MAX_CHANNELS))

ifeq ($(USE_OPENSSL),1)
    $(info - USE OPENSSL)
    CFLAGS += -DUSE_OPENSSL
endif

#CFLAGS += -DUSE_GOSSIP_QUERY

# for syscall()
CFLAGS += -D_GNU_SOURCE

$(info -----------------------------)
