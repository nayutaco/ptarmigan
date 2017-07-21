INSTALL_DIR = $(CURDIR)/install

all: default

default:
	make -C ucoin
	make -C ucoind
	make -C ucoincli
	make -C showdb
	mkdir -p $(INSTALL_DIR)
	-@rm -rf $(INSTALL_DIR)/ucoind $(INSTALL_DIR)/ucoincli $(INSTALL_DIR)/showdb
	cp ucoind/ucoind $(INSTALL_DIR)/
	cp ucoincli/ucoincli $(INSTALL_DIR)/
	cp showdb/showdb $(INSTALL_DIR)/

clean:
	make -C ucoind clean
	make -C ucoincli clean
	-@rm -rf $(INSTALL_DIR)/ucoind $(INSTALL_DIR)/ucoincli $(INSTALL_DIR)/showdb

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

example_clean:
	-@rm -rf $(INSTALL_DIR)/*.cnl $(INSTALL_DIR)/node_3333 $(INSTALL_DIR)/node_4444 $(INSTALL_DIR)/node_5555 $(INSTALL_DIR)/conf $(INSTALL_DIR)/pay4444_3333_5555.conf
