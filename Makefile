INSTALL_DIR = $(CURDIR)/install

default:
	make -C ucoin
	make -C ucoind
	make -C ucoincli
	make -C showdb
	make -C routing
	mkdir -p $(INSTALL_DIR)
	-@rm -rf $(INSTALL_DIR)/ucoind $(INSTALL_DIR)/ucoincli $(INSTALL_DIR)/showdb
	cp ucoind/ucoind $(INSTALL_DIR)/
	cp ucoincli/ucoincli $(INSTALL_DIR)/
	cp showdb/showdb $(INSTALL_DIR)/
	cp routing/routing $(INSTALL_DIR)/

all: lib default

clean:
	make -C ucoin clean
	make -C ucoind clean
	make -C ucoincli clean
	make -C showdb clean
	make -C routing clean
	-@rm -rf $(INSTALL_DIR)/ucoind $(INSTALL_DIR)/ucoincli $(INSTALL_DIR)/showdb $(INSTALL_DIR)/routing GPATH GRTAGS GSYMS GTAGS

full: git_subs lib default

distclean: lib_clean clean

update:
	make -C ucoin clean
	make clean
	make default

lib:
	make -C ucoin/libs
	make -C libs
	make -C ucoin

lib_clean:
	make -C ucoin/libs clean
	make -C libs clean
	make -C ucoin clean

git_subs:
	git submodule update --init --recursive
