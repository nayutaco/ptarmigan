GTEST_DIR = ../../gtest
OBJECT_DIRECTORY = _ggtest

CXX=g++
MK := mkdir
RM := rm -rf

TEST_TARGET_SRC += \
	test_ln_proto_updatechannel.cpp \
	test_ln_msg_close.cpp \
	test_ln_msg_normalope.cpp \
	test_ln_msg_anno.cpp \
	test_ln_bolt.cpp \
	test_ln_htlcflag.cpp \
	test_ln.cpp \
	test_ln_node.cpp \
	test_ln_proto_init.cpp \
	test_ln_proto_openchannel.cpp \
	test_ln_proto_acceptchannel.cpp \
	test_ln_proto_updateaddhtlc.cpp \
	test_ln_proto_updatefee.cpp \
	test_ln_bech32.cpp

# TEST_TARGET_SRC += \
# 	test_ln_msg_anno_gossip.cpp \
# 	test_ln_anno.cpp

# #remove -lz
# TEST_TARGET_SRC += \
# 	test_ln_msg_anno_gossip_zlib.cpp

include ../../options.mak

################################
# GoogleTest

# Flags passed to the preprocessor.
# Set Google Test's header directory as a system directory, such that
# the compiler doesn't generate warnings in Google Test headers.
CPPFLAGS += -isystem $(GTEST_DIR)/.. -DUNITTEST -D_GLIBCXX_USE_CXX11_ABI=1 $(CFLAGS)
CPPFLAGS += -DNDEBUG
CPPFLAGS += -DPTARM_DEBUG
CPPFLAGS += -DPTARM_DEBUG_MEM
#CPPFLAGS += -DPTARM_USE_PRINTFUNC

# Flags passed to the C++ compiler.
CXXFLAGS += -g -Wall -Wextra -pthread -Wno-unused-parameter -Wno-sign-compare --coverage -fpermissive
#CXXFLAGS += -fsanitize=leak
#CXXFLAGS += -fsanitize=address
CXXFLAGS += -I../../utl
CXXFLAGS += -I../../btc
CXXFLAGS += -I..
CXXFLAGS += -I../../libs/install/include
CXXFLAGS += -I../../libs/mbedtls_config -DMBEDTLS_CONFIG_FILE='<config-ptarm.h>'

CXXFLAGS += -ffunction-sections -fdata-sections -fno-strict-aliasing -fstack-protector -D_FORTIFY_SOURCE=1
LDFLAGS  += -L../../libs/install/lib -lmbedcrypto -lbase58 -lz
LDFLAGS  += -Wl,--gc-sections


TEST_SRC_FILE_NAMES = $(notdir $(TEST_TARGET_SRC))
TEST_PATHS = $(call remduplicates, $(dir $(TEST_TARGET_SRC) ) )
TEST_OBJECTS = $(addprefix $(OBJECT_DIRECTORY)/, $(TEST_SRC_FILE_NAMES:.cpp=) )


vpath %.cpp $(TEST_PATHS)


all: .Depend unittest 

unittest: $(OBJECT_DIRECTORY) $(GTEST_DIR)/gtest_main.a $(TEST_OBJECTS)

$(OBJECT_DIRECTORY):
	@echo @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
	@echo @ Google Test: $(CURDIR)
	@echo @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
	@$(MK) $@

# Create objects from CPP SRC files
$(OBJECT_DIRECTORY)/%: %.cpp
	@echo Compiling file: $(notdir $<) $@
	@$(CXX) -DSVCALL_AS_NORMAL_FUNCTION $(CPPFLAGS) $(CXXFLAGS) $(INC_PATHS) $(GTEST_DIR)/gtest_main.a -o $@ $< $(LDFLAGS)

$(GTEST_DIR)/gtest_main.a:
	make -C $(GTEST_DIR)

.Depend:
ifneq ($(MAKECMDGOALS),clean)
	$(foreach SRC,$(TEST_TARGET_SRC),$(CXX) $(CPPFLAGS) $(CXXFLAGS) -MM -MT $(OBJECT_DIRECTORY)/$(SRC:.cpp=.o) $(SRC) >> .Depend;)
endif

rmlcov:
	$(RM) $(OBJECT_DIRECTORY)/*.gcda *.gcda

clean:
	@$(RM) $(OBJECT_DIRECTORY) .Depend

clobber: rmlcov clean
	make -C $(GTEST_DIR) clean
	$(RM) $(OBJECT_DIRECTORY) *.gcno

exec: rmlcov
	$(RM) $(OBJECT_DIRECTORY)/lcov.info
	$(foreach EXEC,$(TEST_OBJECTS),$(EXEC) &&) echo

info:
	@echo TEST_TARGET_SRC=$(TEST_TARGET_SRC)
	@echo TEST_SRC_FILE_NAMES=$(TEST_SRC_FILE_NAMES)
	@echo TEST_PATHS=$(TEST_PATHS)
	@echo TEST_OBJECTS=$(TEST_OBJECTS)

lcov:
	lcov -c -d . -o $(OBJECT_DIRECTORY)/lcov.info
	genhtml -o $(OBJECT_DIRECTORY)/lcovhtml $(OBJECT_DIRECTORY)/lcov.info

valgrind:
	valgrind --leak-check=full --show-leak-kinds=all $(OBJECT_DIRECTORY)/unittest

################################


-include .Depend
