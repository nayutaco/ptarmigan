PRJ_PATH = .
COMMON_PATH = ..
OBJECT_DIRECTORY = _build
OUTPUT_BINARY_DIRECTORY = .

######################################
#CFLAGS_USER
#CFLAGS_USER += -DPTARM_DEBUG_MEM
######################################

include ../options.mak

#echo suspend
ifeq ("$(VERBOSE)","1")
NO_ECHO :=
else
NO_ECHO := @
endif

# Toolchain commands
CC              := "$(GNU_PREFIX)gcc"
AS              := "$(GNU_PREFIX)as"
AR              := "$(GNU_PREFIX)ar" -r
LD              := "$(GNU_PREFIX)ld"
NM              := "$(GNU_PREFIX)nm"
OBJDUMP         := "$(GNU_PREFIX)objdump"
OBJCOPY         := "$(GNU_PREFIX)objcopy"
SIZE            := "$(GNU_PREFIX)size"
MK              := mkdir
RM              := rm -rf

#function for removing duplicates in a list
remduplicates = $(strip $(if $1,$(firstword $1) $(call remduplicates,$(filter-out $(firstword $1),$1))))

#sources project
ifeq ("$(BUILD_PTARMD)","LIB")
	OUTPUT_FILENAME := libptarm.so
	C_SOURCE_FILES += $(PRJ_PATH)/ptarmd_lib.c
	C_SOURCE_FILES += $(PRJ_PATH)/co_nayuta_lightning_PtarmiganNative.c
	INC_PATHS += $(BUILD_PTARMD_LIB_INCPATHS)
else
	OUTPUT_FILENAME := ptarmd
	C_SOURCE_FILES += $(PRJ_PATH)/ptarmd_main.c
endif
C_SOURCE_FILES += $(PRJ_PATH)/ptarmd.c
C_SOURCE_FILES += $(PRJ_PATH)/p2p.c
C_SOURCE_FILES += $(PRJ_PATH)/lnapp.c
C_SOURCE_FILES += $(PRJ_PATH)/lnapp_manager.c
C_SOURCE_FILES += $(PRJ_PATH)/cmd_json.c
C_SOURCE_FILES += $(PRJ_PATH)/monitoring.c
C_SOURCE_FILES += $(PRJ_PATH)/conf.c
C_SOURCE_FILES += $(PRJ_PATH)/wallet.c

#includes common to all targets
INC_PATHS += -I$(PRJ_PATH)
INC_PATHS += -I$(COMMON_PATH)/utl
INC_PATHS += -I$(COMMON_PATH)/btc
INC_PATHS += -I$(COMMON_PATH)/ln
INC_PATHS += -I$(COMMON_PATH)/libs/install/include

# Sorting removes duplicates
BUILD_DIRECTORIES := $(sort $(OBJECT_DIRECTORY) $(OUTPUT_BINARY_DIRECTORY))

######################################
#CFLAGS
######################################

CFLAGS += -std=gnu99
CFLAGS += -W -Wall -Werror -Wextra

# keep every function in separate section. This will allow linker to dump unused functions
CFLAGS += -ffunction-sections -fdata-sections -fno-strict-aliasing
#CFLAGS += -flto -fno-builtin

# others
CFLAGS += $(INC_PATHS)

ifeq ($(NODE_TYPE),BITCOIND)
	C_SOURCE_FILES += $(PRJ_PATH)/btcrpc_bitcoind.c
endif
ifeq ($(NODE_TYPE),BITCOINJ)
	C_SOURCE_FILES += $(PRJ_PATH)/btcrpc_bitcoinj.c
	C_SOURCE_FILES += $(PRJ_PATH)/jni/btcj_jni.c
	INC_PATHS += $(BUILD_PTARMD_LIB_INCPATHS)
	LIBS += $(USE_SPV_JVM) -ljvm
endif

ifeq ($(ENABLE_PLOG_TO_STDOUT_PTARMD),1)
	CFLAGS += -DENABLE_PLOG_TO_STDOUT
endif

CFLAGS += -DMAX_CHANNELS=$(MAX_CHANNELS)

ifeq ("$(BUILD_PTARMD)","LIB")
	CFLAGS += -fPIC
endif

######################################
#LDFLAGS
######################################

# keep every function in separate section. This will allow linker to dump unused functions
#LDFLAGS += -Xlinker -Map=$(OBJECT_DIRECTORY)/$(OUTPUT_FILENAME).map

# let linker to dump unused sections
LDFLAGS += -Wl,--gc-sections
LDFLAGS += -pthread

#Link Library
LIBS += -L$(COMMON_PATH)/libs/install/lib
LIBS += -L$(COMMON_PATH)/ln -lln
LIBS += -L$(COMMON_PATH)/btc -lbtc
LIBS += -L$(COMMON_PATH)/utl -lutl
LIBS += -ljansson
LIBS += -lcurl -lrt -lz
LIBS += -ljsonrpcc -lev -lm
LIBS += -linih
LIBS += -llmdb -lbase58 -lmbedcrypto
LIBS += -lstdc++


######################################
#target
######################################

#default target - first one defined
ifeq ("$(BUILD_PTARMD)","LIB")
default: libdebug
else
default: debug
endif

#target for printing all targets
help:
	@echo following targets are available:
	@echo 	debug release


C_SOURCE_FILE_NAMES = $(notdir $(C_SOURCE_FILES))
C_PATHS = $(call remduplicates, $(dir $(C_SOURCE_FILES) ) )
C_OBJECTS = $(addprefix $(OBJECT_DIRECTORY)/, $(C_SOURCE_FILE_NAMES:.c=.o) )

vpath %.c $(C_PATHS)

OBJECTS = $(C_OBJECTS) $(ASM_OBJECTS)

debug: CFLAGS += $(CFLAGS_USER)
debug: CFLAGS += -ggdb3 -O0
debug: LDFLAGS += -ggdb3 -O0
debug: $(BUILD_DIRECTORIES) $(OBJECTS)
	@echo [DEBUG]Linking target: $(OUTPUT_FILENAME)
	@echo [DEBUG]CFLAGS=$(CFLAGS)
	@echo [DEBUG]LIBS=$(LIBS)
	$(NO_ECHO)$(CC) $(LDFLAGS) $(OBJECTS) $(LIBS) -o $(OUTPUT_BINARY_DIRECTORY)/$(OUTPUT_FILENAME)

libdebug: CFLAGS += $(CFLAGS_USER)
libdebug: CFLAGS += -ggdb3 -O0
libdebug: LDFLAGS += -ggdb3 -O0
libdebug: $(BUILD_DIRECTORIES) $(OBJECTS)
	@echo [DEBUG]Linking target: $(OUTPUT_FILENAME)
	@echo [DEBUG]CFLAGS=$(CFLAGS)
	@echo [DEBUG]LIBS=$(LIBS)
	$(NO_ECHO)$(CC) -shared $(LDFLAGS) $(OBJECTS) $(LIBS) -o $(OUTPUT_BINARY_DIRECTORY)/$(OUTPUT_FILENAME)

release: CFLAGS += $(CFLAGS_USER)
release: CFLAGS += -DNDEBUG -O3
release: LDFLAGS += -O3
release: $(BUILD_DIRECTORIES) $(OBJECTS)
	@echo [RELEASE]Linking target: $(OUTPUT_FILENAME)
	$(NO_ECHO)$(CC) $(LDFLAGS) $(OBJECTS) $(LIBS) -o $(OUTPUT_BINARY_DIRECTORY)/$(OUTPUT_FILENAME)

## Create build directories
$(BUILD_DIRECTORIES):
	$(MK) $@

# Create objects from C SRC files
$(OBJECT_DIRECTORY)/%.o: %.c
	@echo Compiling C file: $(notdir $<)
	$(NO_ECHO)$(CC) $(CFLAGS) $(INC_PATHS) -c -o $@ $<

# Link
$(OUTPUT_BINARY_DIRECTORY)/$(OUTPUT_FILENAME): $(BUILD_DIRECTORIES) $(OBJECTS)
	@echo Linking target: $(OUTPUT_FILENAME)
	$(NO_ECHO)$(CC) $(LDFLAGS) $(OBJECTS) $(LIBS) -o $(OUTPUT_BINARY_DIRECTORY)/$(OUTPUT_FILENAME)

clean:
	$(RM) $(OBJECT_DIRECTORY) $(OUTPUT_BINARY_DIRECTORY)/$(OUTPUT_FILENAME) $(OUTPUT_BINARY_DIRECTORY)/*.gcno .Depend

lcov:
	lcov -c -d $(OBJECT_DIRECTORY) -o $(OBJECT_DIRECTORY)/lcov.info
	genhtml -o $(OBJECT_DIRECTORY)/lcovhtml $(OBJECT_DIRECTORY)/lcov.info

test:
	$(MAKE) -C tests
	$(MAKE) -C tests exec

################################

.Depend:
ifneq ($(MAKECMDGOALS),clean)
	@$(foreach SRC,$(C_SOURCE_FILES),$(CC) $(CFLAGS) -MM -MT $(OBJECT_DIRECTORY)/$(notdir $(SRC:%.c=%.o)) $(SRC) >> .Depend;)
endif

-include .Depend
