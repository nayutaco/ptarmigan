INSTALL_DIR = $(CURDIR)/install

all: lib

lib: mk_install mk_jsonrpc_c mk_inih

mk_install:
	@mkdir -p $(INSTALL_DIR)
	@mkdir -p $(INSTALL_DIR)/include
	@mkdir -p $(INSTALL_DIR)/lib

mk_jsonrpc_c:
	cd jsonrpc-c; autoreconf -i ; ./configure --prefix=$(INSTALL_DIR) --disable-shared ; make CFLAGS=-DNO_CHECK_LOCALHOST LDFLAGS=-lm ; make install ; cd ..

mk_inih:
	cd inih/extra ; EXTRACCFLAGS="-g -O2 -D'INI_INLINE_COMMENT_PREFIXES=\"#\"' -DINI_STOP_ON_FIRST_ERROR=1" make -f Makefile.static ; cd ../..
	@cp inih/extra/libinih.a $(INSTALL_DIR)/lib
	@mkdir -p $(INSTALL_DIR)/include/inih
	@cp inih/ini.h $(INSTALL_DIR)/include/inih/

clean:
	-make -C jsonrpc-c clean
	-make -C inih/extra -f Makefile.static clean
	-$(RM) -rf $(INSTALL_DIR)
