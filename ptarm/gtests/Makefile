GTEST_DIR = ./gtest
OBJECT_DIRECTORY = _ggtest

CXX=g++
MK := mkdir
RM := rm -rf

#fffの fake関数が名前衝突するので、同時に1つだけしかテストしない
TEST_TARGET_SRC += test_ptarm.cpp


################################
# GoogleTest

# Flags passed to the preprocessor.
# Set Google Test's header directory as a system directory, such that
# the compiler doesn't generate warnings in Google Test headers.
CPPFLAGS += -isystem -I$(GTEST_DIR) -DUNITTEST -D_GLIBCXX_USE_CXX11_ABI=1
CPPFLAGS += -DNDEBUG
CPPFLAGS += -DPTARM_DEBUG
CPPFLAGS += -DPTARM_DEBUG_MEM
#CPPFLAGS += -DPTARM_USE_PRINTFUNC

# Flags passed to the C++ compiler.
CXXFLAGS += -g -Wall -Wextra -pthread -Wno-unused-parameter -Wno-sign-compare --coverage -fpermissive
#CXXFLAGS += -fsanitize=leak
#CXXFLAGS += -fsanitize=address
CXXFLAGS += -I../include -I../src/inc -I../src/inc/ln -I../src -I../src/ln -I../src/ln
CXXFLAGS += -I../libs/install/include
CXXFLAGS += -I../libs/mbedtls_config -DMBEDTLS_CONFIG_FILE='<config-ptarm.h>'

CXXFLAGS += -ffunction-sections -fdata-sections -fno-strict-aliasing -fstack-protector -D_FORTIFY_SOURCE=1
LDFLAGS  += -L../libs/install/lib -lmbedcrypto -lbase58 -lsodium
LDFLAGS  += -Wl,--gc-sections


TEST_SRC_FILE_NAMES = $(notdir $(TEST_TARGET_SRC))
TEST_PATHS = $(call remduplicates, $(dir $(TEST_TARGET_SRC) ) )
TEST_OBJECTS = $(addprefix $(OBJECT_DIRECTORY)/, $(TEST_SRC_FILE_NAMES:.cpp=.o) )


vpath %.cpp $(TEST_PATHS)


all: .Depend unittest

unittest : $(OBJECT_DIRECTORY) $(GTEST_DIR)/gtest_main.a $(TEST_OBJECTS)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $(TEST_OBJECTS) $(GTEST_DIR)/gtest_main.a -o $(OBJECT_DIRECTORY)/$@ $(LDFLAGS)

$(OBJECT_DIRECTORY):
	@echo @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
	@echo @ Google Test
	@echo @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
	@$(MK) $@

# Create objects from C SRC files
$(OBJECT_DIRECTORY)/%.o: %.cpp
	@echo Compiling file: $(notdir $<) $@
	@$(CXX) -DSVCALL_AS_NORMAL_FUNCTION $(CPPFLAGS) $(CXXFLAGS) $(INC_PATHS) -c -o $@ $<

$(GTEST_DIR)/gtest_main.a:
	make -C $(GTEST_DIR)

.Depend:
	$(foreach SRC,$(TEST_TARGET_SRC),$(CXX) $(CPPFLAGS) $(CXXFLAGS) -MM -MT $(OBJECT_DIRECTORY)/$(SRC:.cpp=.o) $(SRC) >> .Depend;)

rmlcov :
	$(RM) $(OBJECT_DIRECTORY)/*.gcda

clean :
	@$(RM) $(OBJECT_DIRECTORY) .Depend

clobber : clean
	make -C $(GTEST_DIR) clean

exec: rmlcov
	$(RM) $(OBJECT_DIRECTORY)/lcov.info
	$(OBJECT_DIRECTORY)/unittest

info:
	@echo TEST_TARGET_SRC=$(TEST_TARGET_SRC)
	@echo TEST_SRC_FILE_NAMES=$(TEST_SRC_FILE_NAMES)
	@echo TEST_PATHS=$(TEST_PATHS)
	@echo TEST_OBJECTS=$(TEST_OBJECTS)

lcov:
	lcov -c -d $(OBJECT_DIRECTORY) -o $(OBJECT_DIRECTORY)/lcov.info
	genhtml -o $(OBJECT_DIRECTORY)/lcovhtml $(OBJECT_DIRECTORY)/lcov.info

valgrind:
	valgrind --leak-check=full --show-leak-kinds=all $(OBJECT_DIRECTORY)/unittest

################################


-include .Depend
