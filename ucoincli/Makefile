OUTPUT_FILENAME := ucoincli
PRJ_PATH =
COMMON_PATH = ../
OBJECT_DIRECTORY = _build
OUTPUT_BINARY_DIRECTORY = .

#GNU_PREFIX := arm-none-eabi-


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
C_SOURCE_FILES += $(PRJ_PATH)ucoincli.c
C_SOURCE_FILES += $(COMMON_PATH)cmn/conf.c
C_SOURCE_FILES += $(COMMON_PATH)cmn/misc.c
C_SOURCE_FILES += $(COMMON_PATH)cmn/btcrpc.c

#includes common to all targets
INC_PATHS += -I$(COMMON_PATH)include
INC_PATHS += -I$(COMMON_PATH)ucoin/include
INC_PATHS += -I$(COMMON_PATH)libs/install/include
INC_PATHS += -I$(COMMON_PATH)ucoin/libs/install/include

# Sorting removes duplicates
BUILD_DIRECTORIES := $(sort $(OBJECT_DIRECTORY) $(OUTPUT_BINARY_DIRECTORY))

######################################
#CFLAGS
######################################
# cpu
#CFLAGS += -mcpu=cortex-m0
#CFLAGS += -mthumb -mabi=aapcs
#CFLAGS += -mfloat-abi=soft

CFLAGS += -std=gnu99
CFLAGS += -W -Wall

# keep every function in separate section. This will allow linker to dump unused functions
CFLAGS += -ffunction-sections -fdata-sections -fno-strict-aliasing
#CFLAGS += -flto -fno-builtin

# others
CFLAGS += $(INC_PATHS)
CFLAGS += -DNETKIND=$(NETKIND)


######################################
#LDFLAGS
######################################
# cpu
#LDFLAGS += -mcpu=cortex-m0

# keep every function in separate section. This will allow linker to dump unused functions
#LDFLAGS += -Xlinker -Map=$(LISTING_DIRECTORY)/$(OUTPUT_FILENAME).map

# let linker to dump unused sections
LDFLAGS += -Wl,--gc-sections
LDFLAGS += -pthread

# use newlib in nano version
#LDFLAGS += --specs=nano.specs -lc -lnosys

#Link Library
LIBS += -L$(COMMON_PATH)/libs/install/lib -ljansson -lcurl -linih
LIBS += -L$(COMMON_PATH)/ucoin -lucoin
LIBS += -L$(COMMON_PATH)/ucoin/libs/install/lib -lbase58 -lmbedcrypto -lsodium


######################################
#target
######################################

#default target - first one defined
default: debug

#target for printing all targets
help:
	@echo following targets are available:
	@echo 	debug release


C_SOURCE_FILE_NAMES = $(notdir $(C_SOURCE_FILES))
C_PATHS = $(call remduplicates, $(dir $(C_SOURCE_FILES) ) )
C_OBJECTS = $(addprefix $(OBJECT_DIRECTORY)/, $(C_SOURCE_FILE_NAMES:.c=.o) )

#ASM_SOURCE_FILE_NAMES = $(notdir $(ASM_SOURCE_FILES))
#ASM_PATHS = $(call remduplicates, $(dir $(ASM_SOURCE_FILES) ))
#ASM_OBJECTS = $(addprefix $(OBJECT_DIRECTORY)/, $(ASM_SOURCE_FILE_NAMES:.s=.o) )

vpath %.c $(C_PATHS)

OBJECTS = $(C_OBJECTS) $(ASM_OBJECTS)

debug: CFLAGS += -ggdb3 -O0 --coverage
debug: LDFLAGS += -ggdb3 -O0 --coverage
debug: $(BUILD_DIRECTORIES) $(OBJECTS)
	@echo [DEBUG]Linking target: $(OUTPUT_FILENAME)
	@echo [DEBUG]CFLAGS=$(CFLAGS) > /dev/null
	$(NO_ECHO)$(CC) $(LDFLAGS) $(OBJECTS) $(LIBS) -o $(OUTPUT_BINARY_DIRECTORY)/$(OUTPUT_FILENAME)

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
#	@echo Compiling C file: $(notdir $<): $(CFLAGS)
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

################################

.Depend:
ifneq ($(MAKECMDGOALS),clean)
	@$(foreach SRC,$(C_SOURCE_FILES),$(CC) $(CFLAGS) -MM -MT $(SRC:$(PRJ_PATH)%.c=$(OBJECT_DIRECTORY)/%.o) $(SRC) >> .Depend;)
endif

-include .Depend
