PROJECT_NAME := libln.a
OBJECT_DIRECTORY = _build
PRJ_PATH = .
OUTPUT_BINARY_DIRECTORY = .
OUTPUT_FILENAME := $(PROJECT_NAME)

######################################
#CFLAGS_USER
CFLAGS_USER = -DPTARM_USE_RNG
#CFLAGS_USER += -DPTARM_DEBUG_MEM
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
C_SOURCE_FILES += $(PRJ_PATH)/ln.c
C_SOURCE_FILES += $(PRJ_PATH)/ln_script.c
C_SOURCE_FILES += $(PRJ_PATH)/ln_derkey.c
C_SOURCE_FILES += $(PRJ_PATH)/ln_msg_establish.c
C_SOURCE_FILES += $(PRJ_PATH)/ln_msg_close.c
C_SOURCE_FILES += $(PRJ_PATH)/ln_msg_normalope.c
C_SOURCE_FILES += $(PRJ_PATH)/ln_msg_setupctl.c
C_SOURCE_FILES += $(PRJ_PATH)/ln_msg_anno.c
C_SOURCE_FILES += $(PRJ_PATH)/ln_node.c
C_SOURCE_FILES += $(PRJ_PATH)/ln_misc.c
C_SOURCE_FILES += $(PRJ_PATH)/ln_onion.c
C_SOURCE_FILES += $(PRJ_PATH)/ln_db_lmdb.c
C_SOURCE_FILES += $(PRJ_PATH)/ln_enc_auth.c
C_SOURCE_FILES += $(PRJ_PATH)/ln_print.c
C_SOURCE_FILES += $(PRJ_PATH)/ln_signer.c
C_SOURCE_FILES += $(PRJ_PATH)/ln_segwit_addr.c

CPP_SOURCE_FILES += $(PRJ_PATH)/ln_routing.cpp

#includes common to all targets
INC_PATHS += -I../utl
INC_PATHS += -I../btc
INC_PATHS += -I.
INC_PATHS += -I../libs/install/include
INC_PATHS += -I../libs/boost

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
CFLAGS_CMN += -I../libs/mbedtls_config -DMBEDTLS_CONFIG_FILE='<config-ptarm.h>'

# others
CFLAGS_CMN += $(CFLAGS_USER)
CFLAGS_CMN += -DNETKIND=$(NETKIND)

ifeq ($(USE_SPV),1)
CFLAGS += -DUSE_SPV
endif

ifeq ($(DISABLE_PRINTFUND),0)
CFLAGS_CMN += -DPTARM_USE_PRINTFUNC
endif

ifeq ($(ENABLE_DEVELOPER_MODE),1)
CFLAGS_CMN += -DDEVELOPER_MODE
endif

CFLAGS += -DMAX_CHANNELS=$(MAX_CHANNELS)

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
	$(MAKE) -C ../libs

debug: CFLAGS_CMN += -DDEBUG -DPTARM_DEBUG
debug: CFLAGS_CMN += -ggdb3 -O0
debug: LDFLAGS += -ggdb3 -O0
debug: $(BUILD_DIRECTORIES) $(OBJECTS)
	@echo [DEBUG]Linking target: $(OUTPUT_FILENAME)
	@echo [DEBUG]CFLAGS=$(CFLAGS) $(CFLAGS_CMN)
	$(NO_ECHO)$(LD) -r $(OBJECTS) -o ptarm_tmp.o
	$(NO_ECHO)$(OBJCOPY) --localize-hidden ptarm_tmp.o ptarm_lib.o
	$(NO_ECHO)$(AR) $(OUTPUT_BINARY_DIRECTORY)/$(OUTPUT_FILENAME) ptarm_lib.o
	$(NO_ECHO)$(RM) ptarm_tmp.o ptarm_lib.o

#release: CFLAGS_CMN += -DNDEBUG
release: CFLAGS_CMN += -O3
#release: CFLAGS_CMN +=-Werror
release: LDFLAGS += -O3
release: $(BUILD_DIRECTORIES) $(OBJECTS)
	@echo [RELEASE]Linking target: $(OUTPUT_FILENAME)
	$(NO_ECHO)$(LD) -r $(OBJECTS) -o ptarm_tmp.o
	$(NO_ECHO)$(OBJCOPY) --localize-hidden ptarm_tmp.o ptarm_lib.o
	$(NO_ECHO)$(AR) $(OUTPUT_BINARY_DIRECTORY)/$(OUTPUT_FILENAME) ptarm_lib.o
	$(NO_ECHO)$(RM) ptarm_tmp.o ptarm_lib.o

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
	cppcheck --enable=all --suppress=missingIncludeSystem -D__ORDER_LITTLE_ENDIAN__ -DDEBUG -DPTARM_DEBUG -DPTARM_USE_PRINTFUNC -DPTARM_DEBUG_MEM $(INC_PATHS) $(PRJ_PATH)/*.c

clean:
	$(RM) $(OBJECT_DIRECTORY) $(OUTPUT_BINARY_DIRECTORY)/$(OUTPUT_FILENAME) .Depend
	$(MAKE) -C tests clean

test:
	$(MAKE) -C tests
	$(MAKE) -C tests exec

################################

.Depend:
ifneq ($(MAKECMDGOALS),clean)
	@$(foreach SRC,$(C_SOURCE_FILES),$(CC) $(CFLAGS) $(CFLAGS_CMN) $(INC_PATHS) -MM -MT $(OBJECT_DIRECTORY)/$(notdir $(SRC:%.c=%.o)) $(SRC) >> .Depend; )
	@$(foreach SRC,$(CPP_SOURCE_FILES),$(CXX) $(CPPFLAGS) $(CFLAGS_CMN) $(INC_PATHS) -MM -MT $(OBJECT_DIRECTORY)/$(notdir $(SRC:%.cpp=%.o)) $(SRC) >> .Depend; )
endif

-include .Depend
