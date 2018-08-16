INSTALL_DIR = $(CURDIR)/install

all: lib

lib: mk_install mk_jsonrpc_c mk_inih mk_base58 mk_mbedtls mk_lmdb

mk_install:
	@mkdir -p $(INSTALL_DIR)
	@mkdir -p $(INSTALL_DIR)/include
	@mkdir -p $(INSTALL_DIR)/lib

mk_jsonrpc_c:
	cd jsonrpc-c; autoreconf -i ; ./configure --prefix=$(INSTALL_DIR) --disable-shared ; $(MAKE) CFLAGS=-DCHECK_LOCALHOST LDFLAGS=-lm ; $(MAKE) install ; cd ..

mk_inih:
	cd inih/extra ; EXTRACCFLAGS="-g -O2 -D'INI_INLINE_COMMENT_PREFIXES=\"#\"' -DINI_STOP_ON_FIRST_ERROR=1" $(MAKE) -f Makefile.static ; cd ../..
	@cp inih/extra/libinih.a $(INSTALL_DIR)/lib
	@mkdir -p $(INSTALL_DIR)/include/inih
	@cp inih/ini.h $(INSTALL_DIR)/include/inih/

mk_base58:
	cd libbase58; autoreconf -i ; ./configure --prefix=$(INSTALL_DIR) --disable-shared ; $(MAKE) ; $(MAKE) install ; cd ..
	@rm -rf libbase58/compile

mk_lmdb:
	$(MAKE) -C lmdb/libraries/liblmdb
	cp lmdb/libraries/liblmdb/liblmdb.a $(INSTALL_DIR)/lib/
	cp lmdb/libraries/liblmdb/lmdb.h $(INSTALL_DIR)/include/

mk_mbedtls:
	CFLAGS="-I`pwd`/mbedtls_config -DMBEDTLS_CONFIG_FILE='\"config-ptarm.h\"'" $(MAKE) -C mbedtls
	cp mbedtls/library/libmbedcrypto.a $(INSTALL_DIR)/lib/
	cp -ra mbedtls/include/* $(INSTALL_DIR)/include/

clean_mbedtls:
	-$(MAKE) -C mbedtls clean

mbedtls_all: clean_mbedtls mk_mbedtls

clean:
	-$(MAKE) -C jsonrpc-c clean
	-$(MAKE) -C inih/extra -f Makefile.static clean
	-$(MAKE) -C libbase58 clean
	-$(MAKE) -C lmdb/libraries/liblmdb clean
	-$(MAKE) -C mbedtls clean
	-$(RM) -rf $(INSTALL_DIR) bech32

