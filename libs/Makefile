INSTALL_DIR = $(CURDIR)/install

all: lib

lib: mk_install mk_jsonrpc_c mk_inih

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

clean:
	-$(MAKE) -C jsonrpc-c clean
	-$(MAKE) -C inih/extra -f Makefile.static clean
	-$(RM) -rf $(INSTALL_DIR)
