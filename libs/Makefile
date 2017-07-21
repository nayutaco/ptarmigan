INSTALL_DIR = $(CURDIR)/install

all: lib

lib: mk_install mk_curl mk_jansson

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

clean:
	make -C curl clean
	make -C jansson clean
	$(RM) -rf $(INSTALL_DIR)
