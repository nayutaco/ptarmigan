INSTALL_DIR = $(CURDIR)/install

all: lib

lib: mk_install mk_base58 mk_bech32 mk_sodium mk_lmdb mk_mbedtls

mk_install:
	@mkdir -p $(INSTALL_DIR)
	@mkdir -p $(INSTALL_DIR)/include
	@mkdir -p $(INSTALL_DIR)/lib

mk_bech32:
	make -C bech32/ref/c
	cp bech32/ref/c/libbech32.a $(INSTALL_DIR)/lib/
	cp bech32/ref/c/segwit_addr.h $(INSTALL_DIR)/include/

mk_base58:
	cd libbase58; autoreconf -i ; ./configure --prefix=$(INSTALL_DIR) --disable-shared ; make ; make install ; cd ..
	@rm -rf libbase58/compile

mk_sodium:
	cd libsodium; autoreconf -i ; ./configure --prefix=$(INSTALL_DIR) --disable-shared ; make ; make install ; cd ..

mk_lmdb:
	make -C lmdb/libraries/liblmdb
	cp lmdb/libraries/liblmdb/liblmdb.a $(INSTALL_DIR)/lib/
	cp lmdb/libraries/liblmdb/lmdb.h $(INSTALL_DIR)/include/

mk_mbedtls:
	CFLAGS="-I`pwd`/mbedtls_config -DMBEDTLS_CONFIG_FILE='<config-ucoin.h>'" make -C mbedtls
	cp mbedtls/library/libmbedcrypto.a $(INSTALL_DIR)/lib/
	cp -ra mbedtls/include/* $(INSTALL_DIR)/include/

clean:
	-make -C bech32/ref/c clean
	-make -C libbase58 clean
	-make -C libsodium clean
	-make -C lmdb/libraries/liblmdb clean
	-make -C mbedtls clean
	-rm -rf $(INSTALL_DIR)
