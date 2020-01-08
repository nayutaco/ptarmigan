INSTALL_DIR = $(CURDIR)/install
include ./options.mak

.PHONY: build install btconly clean full full_btconly distclean update lib lib_clean git_subs test test_clean test-integration test-i

default: build install

build:
	$(MAKE) -C utl
	$(MAKE) -C btc
	$(MAKE) -C ln
	$(MAKE) -C ptarmd
	$(MAKE) -C ptarmcli
	$(MAKE) -C showdb
	$(MAKE) -C routing

release:
	$(MAKE) -C utl release
	$(MAKE) -C btc release
	$(MAKE) -C ln release
	$(MAKE) -C ptarmd release
	$(MAKE) -C ptarmcli
	$(MAKE) -C showdb
	$(MAKE) -C routing

install:
	-@mkdir -p $(INSTALL_DIR)
ifeq ($(NODE_TYPE),BITCOINJ)
	-cp -ra ptarmd/jni/jar $(INSTALL_DIR)/
endif
	-cp ptarmcli/ptarmcli $(INSTALL_DIR)/
	-cp showdb/showdb $(INSTALL_DIR)/
	-cp routing/routing $(INSTALL_DIR)/
ifeq ("$(BUILD_PTARMD)","LIB")
	-@mkdir -p $(INSTALL_DIR)/jar/
	cp ptarmd/libptarm.so $(INSTALL_DIR)/jar/
else
	cp ptarmd/ptarmd $(INSTALL_DIR)/
endif

all: lib default

btconly:
	$(MAKE) -C utl
	$(MAKE) -C btc
	mkdir -p $(INSTALL_DIR)/ptarmbtc/include
	mkdir -p $(INSTALL_DIR)/ptarmbtc/lib
	mkdir -p $(INSTALL_DIR)/ptarmbtc/src
	cp utl/libutl.a $(INSTALL_DIR)/ptarmbtc/lib/
	cp btc/libbtc.a $(INSTALL_DIR)/ptarmbtc/lib/
	cp -ra utl/*.h $(INSTALL_DIR)/ptarmbtc/include/
	cp -ra btc/*.h $(INSTALL_DIR)/ptarmbtc/include/
	cp libs/install/lib/libbase58.a $(INSTALL_DIR)/ptarmbtc/lib/
	cp libs/install/lib/libmbedcrypto.a $(INSTALL_DIR)/ptarmbtc/lib/
	cp btc/examples/Makefile_ptarmbtc $(INSTALL_DIR)/ptarmbtc/Makefile
	cp btc/examples/tx_create_copy.c $(INSTALL_DIR)/ptarmbtc/src/

clean:
	$(MAKE) -C gtest clean
	$(MAKE) -C utl clean
	$(MAKE) -C btc clean
	$(MAKE) -C ln clean
	$(MAKE) -C ptarmd clean
	$(MAKE) -C ptarmcli clean
	$(MAKE) -C showdb clean
	$(MAKE) -C routing clean
	-@rm -rf $(INSTALL_DIR)/ptarmd $(INSTALL_DIR)/ptarmcli $(INSTALL_DIR)/showdb $(INSTALL_DIR)/routing $(INSTALL_DIR)/jar GPATH GRTAGS GSYMS GTAGS

full: git_subs lib default
full_btconly: git_subs lib btconly

distclean: lib_clean clean

update:
	$(MAKE) -C utl clean
	$(MAKE) -C btc clean
	$(MAKE) -C ln clean
	$(MAKE) clean
	$(MAKE) default

lib:
	$(MAKE) -C libs
	$(MAKE) -C utl
	$(MAKE) -C btc
	$(MAKE) -C ln

lib_clean:
	$(MAKE) -C libs clean
	$(MAKE) -C utl clean
	$(MAKE) -C btc clean
	$(MAKE) -C ln clean

git_subs:
	git submodule update --init --recursive

lcov:
	$(RM) -r ptarmd/_build/lcovhtml ptarmd/_build/lcov.info
	lcov -c -d utl/_build -d btc/_build -d ln/_build -d ptarmd/_build -o ptarmd/_build/lcov.info
	genhtml -o ptarmd/_build/lcovhtml ptarmd/_build/lcov.info

test:
	$(MAKE) -C gtest
	$(MAKE) -C utl test
	$(MAKE) -C btc test
	$(MAKE) -C ln test
	$(MAKE) -C ptarmd test
	$(MAKE) -C btc/examples #make only

test_clean:
	$(MAKE) -C gtest clean
	$(MAKE) -C utl/tests clobber
	$(MAKE) -C btc/tests clobber
	$(MAKE) -C ln/tests clobber
	$(MAKE) -C ptarmd/tests clobber
	$(MAKE) -C btc/examples clean

test-integration: test-i

test-i:
	cd tests/4nodes_test; timeout 280 ./all_test.sh
