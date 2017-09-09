INSTALL_DIR = $(CURDIR)/install

all: lib

lib: mk_install mk_curl mk_jansson mk_jsonrpc_c mk_inih

mk_install:
	@mkdir -p $(INSTALL_DIR)
	@mkdir -p $(INSTALL_DIR)/include
	@mkdir -p $(INSTALL_DIR)/lib

mk_curl:
	cd curl; autoreconf -i ;\
	./configure --prefix=$(INSTALL_DIR) --disable-shared --without-ssl --without-zlib ;\
	make ; make install ; cd ..

mk_jansson:
	cd jansson; autoreconf -i ; ./configure --prefix=$(INSTALL_DIR) --disable-shared ; make ; make install ; cd ..

mk_jsonrpc_c:
	cd jsonrpc-c; autoreconf -i ; ./configure --prefix=$(INSTALL_DIR) --disable-shared ; make CFLAGS=-DCHECK_LOCALHOST LDFLAGS=-lm ; make install ; cd ..

mk_inih:
	cd inih/extra ; CCFLAGS="-g -O2 -DINI_INLINE_COMMENT_PREFIXES=\"\#\" -DINI_STOP_ON_FIRST_ERROR=1" make -f Makefile.static ; cd ../..
	@cp inih/extra/libinih.a $(INSTALL_DIR)/lib
	@mkdir -p $(INSTALL_DIR)/include/inih
	@cp inih/ini.h $(INSTALL_DIR)/include/inih/

clean:
	-make -C curl clean
	-make -C jansson clean
	-make -C jsonrpc-c clean
	-make -C inih/extra -f Makefile.static clean
	-$(RM) -rf $(INSTALL_DIR)
