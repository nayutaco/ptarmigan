INSTALL_DIR = $(CURDIR)/install

default:
	$(MAKE) -C ucoin
	$(MAKE) -C ucoind
	$(MAKE) -C ucoincli
	$(MAKE) -C showdb
	$(MAKE) -C routing
	mkdir -p $(INSTALL_DIR)
	-@rm -rf $(INSTALL_DIR)/ucoind $(INSTALL_DIR)/ucoincli $(INSTALL_DIR)/showdb
	cp ucoind/ucoind $(INSTALL_DIR)/
	cp ucoincli/ucoincli $(INSTALL_DIR)/
	cp showdb/showdb $(INSTALL_DIR)/
	cp routing/routing $(INSTALL_DIR)/

all: lib default

clean:
	$(MAKE) -C ucoin clean
	$(MAKE) -C ucoind clean
	$(MAKE) -C ucoincli clean
	$(MAKE) -C showdb clean
	$(MAKE) -C routing clean
	-@rm -rf $(INSTALL_DIR)/ucoind $(INSTALL_DIR)/ucoincli $(INSTALL_DIR)/showdb $(INSTALL_DIR)/routing GPATH GRTAGS GSYMS GTAGS

full: git_subs lib default

distclean: lib_clean clean

update:
	$(MAKE) -C ucoin clean
	$(MAKE) clean
	$(MAKE) default

lib:
	$(MAKE) -C ucoin/libs
	$(MAKE) -C libs
	$(MAKE) -C ucoin

lib_clean:
	$(MAKE) -C ucoin/libs clean
	$(MAKE) -C libs clean
	$(MAKE) -C ucoin clean

git_subs:
	git submodule update --init --recursive
