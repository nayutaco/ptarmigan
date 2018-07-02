PROJECT_NAME := libucoin.a
OBJECT_DIRECTORY = _build
PRJ_PATH = src
OUTPUT_BINARY_DIRECTORY = .
OUTPUT_FILENAME := $(PROJECT_NAME)

######################################
#CFLAGS_USER
CFLAGS_USER = -DUCOIN_USE_RNG
#CFLAGS_USER += -DUCOIN_DEBUG_MEM
######################################

include ../options.mak

#GNU_PREFIX := arm-none-eabi-

MK := mkdir
RM := rm -rf

#echo suspend
ifeq ("$(VERBOSE)","1")
NO_ECHO :=
else
NO_ECHO := @
endif

# Toolchain commands
CC       		:= "$(GNU_PREFIX)gcc"
CXX      		:= "$(GNU_PREFIX)g++"
AS       		:= "$(GNU_PREFIX)as"
AR       		:= "$(GNU_PREFIX)ar" -r
LD       		:= "$(GNU_PREFIX)ld"
NM       		:= "$(GNU_PREFIX)nm"
OBJDUMP  		:= "$(GNU_PREFIX)objdump"
OBJCOPY  		:= "$(GNU_PREFIX)objcopy"
SIZE    		:= "$(GNU_PREFIX)size"

#function for removing duplicates in a list
remduplicates = $(strip $(if $1,$(firstword $1) $(call remduplicates,$(filter-out $(firstword $1),$1))))

#sources project
C_SOURCE_FILES += $(PRJ_PATH)/ucoin.c
C_SOURCE_FILES += $(PRJ_PATH)/ucoin_buf.c
C_SOURCE_FILES += $(PRJ_PATH)/ucoin_push.c
C_SOURCE_FILES += $(PRJ_PATH)/ucoin_ekey.c
C_SOURCE_FILES += $(PRJ_PATH)/ucoin_util.c
C_SOURCE_FILES += $(PRJ_PATH)/ucoin_keys.c
C_SOURCE_FILES += $(PRJ_PATH)/ucoin_tx.c
C_SOURCE_FILES += $(PRJ_PATH)/ucoin_sw.c
C_SOURCE_FILES += $(PRJ_PATH)/ln/ln.c
C_SOURCE_FILES += $(PRJ_PATH)/ln/ln_script.c
C_SOURCE_FILES += $(PRJ_PATH)/ln/ln_derkey.c
C_SOURCE_FILES += $(PRJ_PATH)/ln/ln_msg_establish.c
C_SOURCE_FILES += $(PRJ_PATH)/ln/ln_msg_close.c
C_SOURCE_FILES += $(PRJ_PATH)/ln/ln_msg_normalope.c
C_SOURCE_FILES += $(PRJ_PATH)/ln/ln_msg_setupctl.c
C_SOURCE_FILES += $(PRJ_PATH)/ln/ln_msg_anno.c
C_SOURCE_FILES += $(PRJ_PATH)/ln/ln_node.c
C_SOURCE_FILES += $(PRJ_PATH)/ln/ln_misc.c
C_SOURCE_FILES += $(PRJ_PATH)/ln/ln_onion.c
C_SOURCE_FILES += $(PRJ_PATH)/ln/ln_db_lmdb.c
C_SOURCE_FILES += $(PRJ_PATH)/ln/ln_enc_auth.c
C_SOURCE_FILES += $(PRJ_PATH)/ln/ln_print.c
C_SOURCE_FILES += $(PRJ_PATH)/ln/ln_signer.c
C_SOURCE_FILES += $(PRJ_PATH)/bech32/segwit_addr.c
#ifeq ($(findstring 1,$(USE_ULOG_UCOIND) $(USE_ULOG_UCOINLIB)), 1)
C_SOURCE_FILES += $(PRJ_PATH)/log/ulog.c
#endif


CPP_SOURCE_FILES += $(PRJ_PATH)/routing/ln_routing.cpp

#includes common to all targets
INC_PATHS += -Iinclude -Isrc/inc -Isrc/inc/ln
INC_PATHS += -Ilibs/install/include

# Sorting removes duplicates
BUILD_DIRECTORIES := $(sort $(OBJECT_DIRECTORY) $(OUTPUT_BINARY_DIRECTORY))

######################################
#CFLAGS_CMN : C/C++ common
######################################
# cpu
#CFLAGS_CMN += -mcpu=cortex-m0
#CFLAGS_CMN += -mthumb -mabi=aapcs
#CFLAGS_CMN += -mfloat-abi=soft

CFLAGS_CMN += -W -Wall -Wno-error=unused-function -fno-common

# keep every function in separate section. This will allow linker to dump unused functions
CFLAGS_CMN += -ffunction-sections -fdata-sections -fno-strict-aliasing
#CFLAGS_CMN += -flto -fno-builtin

# for syscall()
CFLAGS_CMN += -D_GNU_SOURCE

# for mbedtls
CFLAGS_CMN += -Ilibs/mbedtls_config -DMBEDTLS_CONFIG_FILE='<config-ucoin.h>'

# others
CFLAGS_CMN += $(CFLAGS_USER)
CFLAGS_CMN += -DNETKIND=$(NETKIND)

ifeq ($(DISABLE_PRINTFUND),0)
CFLAGS_CMN += -DUCOIN_USE_PRINTFUNC
endif

######################################
#CFLAGS only
######################################

CFLAGS += -std=gnu99


######################################
#LDFLAGS
######################################
# keep every function in separate section. This will allow linker to dump unused functions
#LDFLAGS += -Xlinker -Map=$(OBJECT_DIRECTORY)/$(OUTPUT_FILENAME).map

# let linker to dump unused sections
LDFLAGS += -Wl,--gc-sections


######################################
#target
######################################

#default target - first one defined
default: debug

#building all targets
all:
	$(NO_ECHO)$(MAKE) -f $(MAKEFILE_NAME) -C $(MAKEFILE_DIR) -e cleanobj
	$(NO_ECHO)$(MAKE) -f $(MAKEFILE_NAME) -C $(MAKEFILE_DIR) -e debug

#target for printing all targets
help:
	@echo following targets are available:
	@echo 	debug release


C_SOURCE_FILE_NAMES = $(notdir $(C_SOURCE_FILES))
C_PATHS = $(call remduplicates, $(dir $(C_SOURCE_FILES) ) )
C_OBJECTS = $(addprefix $(OBJECT_DIRECTORY)/, $(C_SOURCE_FILE_NAMES:.c=.o) )

CPP_SOURCE_FILE_NAMES = $(notdir $(CPP_SOURCE_FILES))
CPP_PATHS = $(call remduplicates, $(dir $(CPP_SOURCE_FILES) ) )
CPP_OBJECTS = $(addprefix $(OBJECT_DIRECTORY)/, $(CPP_SOURCE_FILE_NAMES:.cpp=.o) )

vpath %.c $(C_PATHS)
vpath %.cpp $(CPP_PATHS)

OBJECTS = $(C_OBJECTS) $(CPP_OBJECTS)

lib:
	make -C libs

debug: CFLAGS_CMN += -DDEBUG -DUCOIN_DEBUG
debug: CFLAGS_CMN += -ggdb3 -O0
debug: LDFLAGS += -ggdb3 -O0
debug: $(BUILD_DIRECTORIES) $(OBJECTS)
	@echo [DEBUG]Linking target: $(OUTPUT_FILENAME)
	@echo [DEBUG]CFLAGS=$(CFLAGS) $(CFLAGS_CMN)
	$(NO_ECHO)$(LD) -r $(OBJECTS) -o ucoin_tmp.o
	$(NO_ECHO)$(OBJCOPY) --localize-hidden ucoin_tmp.o ucoin_lib.o
	$(NO_ECHO)$(AR) $(OUTPUT_BINARY_DIRECTORY)/$(OUTPUT_FILENAME) ucoin_lib.o
	$(NO_ECHO)$(RM) ucoin_tmp.o ucoin_lib.o

#release: CFLAGS_CMN += -DNDEBUG
release: CFLAGS_CMN += -O3
#release: CFLAGS_CMN +=-Werror
release: LDFLAGS += -O3
release: $(BUILD_DIRECTORIES) $(OBJECTS)
	@echo [RELEASE]Linking target: $(OUTPUT_FILENAME)
	$(NO_ECHO)$(LD) -r $(OBJECTS) -o ucoin_tmp.o
	$(NO_ECHO)$(OBJCOPY) --localize-hidden ucoin_tmp.o ucoin_lib.o
	$(NO_ECHO)$(AR) $(OUTPUT_BINARY_DIRECTORY)/$(OUTPUT_FILENAME) ucoin_lib.o
	$(NO_ECHO)$(RM) ucoin_tmp.o ucoin_lib.o

## Create build directories
$(BUILD_DIRECTORIES):
	$(MK) $@

# Create objects from C SRC files
$(OBJECT_DIRECTORY)/%.o: %.c
	@echo Compiling C file: $(notdir $<)
	$(NO_ECHO)$(CC) $(CFLAGS) $(CFLAGS_CMN) $(INC_PATHS) -c -o $@ $<


# Create objects from C++ SRC files
$(OBJECT_DIRECTORY)/%.o: %.cpp
	@echo Compiling C++ file: $(notdir $<)
	$(NO_ECHO)$(CXX) $(CPPFLAGS) $(CFLAGS_CMN) $(INC_PATHS) -c -o $@ $<


# Link
$(OUTPUT_BINARY_DIRECTORY)/$(OUTPUT_FILENAME): $(BUILD_DIRECTORIES) $(OBJECTS)
	@echo Linking target: $(OUTPUT_FILENAME)
	$(NO_ECHO)$(CC) $(LDFLAGS) $(OBJECTS) $(LIBS) -o $(OUTPUT_BINARY_DIRECTORY)/$(OUTPUT_FILENAME)

cppcheck:
	cppcheck --enable=all --suppress=missingIncludeSystem -D__ORDER_LITTLE_ENDIAN__ -DDEBUG -DUCOIN_DEBUG -DUCOIN_USE_PRINTFUNC -DUCOIN_DEBUG_MEM $(INC_PATHS) $(PRJ_PATH)/*.c

clean:
	$(RM) $(OBJECT_DIRECTORY) $(OUTPUT_BINARY_DIRECTORY)/$(OUTPUT_FILENAME) .Depend

################################

.Depend:
ifneq ($(MAKECMDGOALS),clean)
	@$(foreach SRC,$(C_SOURCE_FILES),$(CC) $(CFLAGS) $(CFLAGS_CMN) $(INC_PATHS) -MM -MT $(OBJECT_DIRECTORY)/$(notdir $(SRC:%.c=%.o)) $(SRC) >> .Depend; )
	@$(foreach SRC,$(CPP_SOURCE_FILES),$(CXX) $(CPPFLAGS) $(CFLAGS_CMN) $(INC_PATHS) -MM -MT $(OBJECT_DIRECTORY)/$(notdir $(SRC:%.cpp=%.o)) $(SRC) >> .Depend; )
endif

-include .Depend
