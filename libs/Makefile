INSTALL_DIR = $(CURDIR)/install
BOOST_VER = 1.68.0
BOOST_VER_FILE = boost_1_68_0

include ../options.mak

ifneq ("$GNU_PREFIX","arm-linux-gnueabihf-")
	HOST=arm-linux
	BOOST_CONV="using gcc : arm : arm-linux-gnueabihf-g++"
else
	BOOST_CONV="using gcc"
endif

ifeq ("$(BUILD_PTARMD)","LIB")
	ADD_CFLAGS = -fPIC
else
	ADD_CFLAGS = 
endif

all: lib

lib: mk_install mk_jsonrpc_c mk_inih mk_base58 mk_lmdb mk_mbedtls mk_boost mk_jansson mk_zlib mk_curl

mk_install:
	@mkdir -p $(INSTALL_DIR)
	@mkdir -p $(INSTALL_DIR)/include
	@mkdir -p $(INSTALL_DIR)/lib
	@mkdir -p $(INSTALL_DIR)/boost

mk_jsonrpc_c:
	cd libev; \
	autoreconf -i ;\
	./configure --prefix=$(INSTALL_DIR) --host=$(HOST) CC=$(GNU_PREFIX)gcc CFLAGS="$(ADD_CFLAGS)" --disable-shared ; \
	$(MAKE) ; \
	$(MAKE) install ; \
	cd ..
	cd jsonrpc-c; \
	autoreconf -i ; \
	./configure --prefix=$(INSTALL_DIR) --host=$(HOST) CC=$(GNU_PREFIX)gcc --with-libev=$(INSTALL_DIR) --disable-shared ; \
	$(MAKE) CFLAGS="-DCHECK_LOCALHOST $(ADD_CFLAGS)"; \
	$(MAKE) install ; \
	cd ..

mk_inih:
	cd inih/extra ; \
	EXTRACCFLAGS="-g -O2 -D'INI_INLINE_COMMENT_PREFIXES=\"#\"' -DINI_STOP_ON_FIRST_ERROR=1 $(ADD_CFLAGS)" $(MAKE) CC=$(GNU_PREFIX)gcc -f Makefile.static ; \
	cd ../..
	@cp inih/extra/libinih.a $(INSTALL_DIR)/lib
	@mkdir -p $(INSTALL_DIR)/include/inih
	@cp inih/ini.h $(INSTALL_DIR)/include/inih/

mk_base58:
	cd libbase58; \
	autoreconf -i ; \
	./configure --prefix=$(INSTALL_DIR) --host=$(HOST) CC=$(GNU_PREFIX)gcc --disable-shared ; \
	$(MAKE) CFLAGS=$(ADD_CFLAGS); \
	$(MAKE) install ; \
	cd ..
	@rm -rf libbase58/compile

mk_lmdb:
	$(MAKE) XCFLAGS=$(ADD_CFLAGS) CC=$(GNU_PREFIX)gcc -C lmdb/libraries/liblmdb
	cp lmdb/libraries/liblmdb/liblmdb.a $(INSTALL_DIR)/lib/
	cp lmdb/libraries/liblmdb/lmdb.h $(INSTALL_DIR)/include/

mk_mbedtls:
	CFLAGS="-I`pwd`/mbedtls_config -DMBEDTLS_CONFIG_FILE='\"config-ptarm.h\"' $(ADD_CFLAGS)" CC=$(GNU_PREFIX)gcc $(MAKE) -C mbedtls
	cp mbedtls/library/libmbedcrypto.a $(INSTALL_DIR)/lib/
	cp -ra mbedtls/include/* $(INSTALL_DIR)/include/
	cp mbedtls_config/* $(INSTALL_DIR)/include/mbedtls/

clean_mbedtls:
	-$(MAKE) -C mbedtls clean

mbedtls_all: clean_mbedtls mk_mbedtls

mk_boost:
	-@if [ ! -f $(BOOST_VER_FILE).tar.gz ]; then\
		rm -rf boost $(BOOST_VER_FILE) $(BOOST_VER_FILE).tar.gz ;\
		wget -O boost.tgz https://dl.bintray.com/boostorg/release/$(BOOST_VER)/source/$(BOOST_VER_FILE).tar.gz &&\
		mv boost.tgz $(BOOST_VER_FILE).tar.gz ;\
	fi
	@if [ ! -f $(BOOST_VER_FILE).tar.gz ]; then\
		wget -O boost.tgz https://sourceforge.net/projects/boost/files/boost/$(BOOST_VER)/$(BOOST_VER_FILE).tar.gz/download &&\
		mv boost.tgz $(BOOST_VER_FILE).tar.gz ;\
	fi
	if [ ! -d boost ]; then\
		rm -rf $(BOOST_VER_FILE) ;\
		tar zxf $(BOOST_VER_FILE).tar.gz ;\
		ln -s $(BOOST_VER_FILE) boost ;\
	fi
	cd boost; \
	./bootstrap.sh; \
	./b2 tools/bcp; \
	perl -pi -e 's/using gcc/$(BOOST_CONV)/g' project-config.jam; \
	./dist/bin/bcp graph $(INSTALL_DIR)/boost; \
	cd ..

mk_jansson:
	cd jansson; \
	autoreconf -i ; \
	./configure --prefix=$(INSTALL_DIR) --host=$(HOST) CC=$(GNU_PREFIX)gcc CFLAGS="-I$(INSTALL_DIR)/include $(ADD_CFLAGS)" --disable-shared ; $(MAKE) ; \
	$(MAKE) install ; \
	cd ..

mk_zlib:
	cd zlib; \
	CC=$(GNU_PREFIX)gcc ./configure --prefix=$(INSTALL_DIR) ; $(MAKE) ; \
	$(MAKE) CFLAGS=$(ADD_CFLAGS); \
	$(MAKE) install ; \
	cd ..

mk_curl:
	cd curl; \
	autoreconf -i ; \
	./configure --prefix=$(INSTALL_DIR) --host=$(HOST) CC=$(GNU_PREFIX)gcc --disable-ftp --disable-ldap --disable-ldaps --disable-rtsp --disable-proxy --disable-dict --disable-telnet --disable-tftp --disable-pop3 --disable-imap --disable-smb --disable-smtp  --disable-gopher --disable-ares --disable-manual --disable-proxy --disable-unix-sockets --disable-verbose --disable-versioned-symbols --enable-hidden-symbols --without-libidn --without-librtmp --without-ssl --disable-shared ; \
	$(MAKE) CFLAGS=$(ADD_CFLAGS); \
	$(MAKE) install ; \
	cd ..

clean:
	-$(MAKE) -C jsonrpc-c clean
	-$(MAKE) -C inih/extra -f Makefile.static clean
	-$(MAKE) -C libbase58 clean
	-$(MAKE) -C lmdb/libraries/liblmdb clean
	-$(MAKE) -C mbedtls clean
	-$(MAKE) -C libev clean
	-$(MAKE) -C jansson clean
	-$(MAKE) -C curl clean
	-$(MAKE) -C zlib clean
	-$(RM) -rf $(INSTALL_DIR) bech32 boost $(BOOST_VER_FILE) $(BOOST_VER_FILE).tar.gz

