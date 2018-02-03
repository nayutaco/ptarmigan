INSTALL_DIR = $(CURDIR)/install

# 0:mainnet, 1:testnet
NETKIND=1

default:
	make -C ucoin NETKIND=$(NETKIND)
	make -C ucoind NETKIND=$(NETKIND)
	make -C ucoincli NETKIND=$(NETKIND)
	make -C showdb NETKIND=$(NETKIND)
	make -C routing NETKIND=$(NETKIND)
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
	make -C ucoin NETKIND=$(NETKIND)

lib_clean:
	make -C ucoin/libs clean
	make -C libs clean
	make -C ucoin clean

git_subs:
	git submodule update --init --recursive
