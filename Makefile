INSTALL_DIR = $(CURDIR)/install

default:
	$(MAKE) -C utl
	$(MAKE) -C btc
	$(MAKE) -C ln
	$(MAKE) -C ptarmd
	$(MAKE) -C ptarmcli
	$(MAKE) -C showdb
	$(MAKE) -C routing
	mkdir -p $(INSTALL_DIR)
	-@rm -rf $(INSTALL_DIR)/ptarmd $(INSTALL_DIR)/ptarmcli $(INSTALL_DIR)/showdb
	cp ptarmd/ptarmd $(INSTALL_DIR)/
	cp ptarmcli/ptarmcli $(INSTALL_DIR)/
	cp showdb/showdb $(INSTALL_DIR)/
	cp routing/routing $(INSTALL_DIR)/

all: lib default

clean:
	$(MAKE) -C gtest clean
	$(MAKE) -C utl clean
	$(MAKE) -C btc clean
	$(MAKE) -C ln clean
	$(MAKE) -C ptarmd clean
	$(MAKE) -C ptarmcli clean
	$(MAKE) -C showdb clean
	$(MAKE) -C routing clean
	-@rm -rf $(INSTALL_DIR)/ptarmd $(INSTALL_DIR)/ptarmcli $(INSTALL_DIR)/showdb $(INSTALL_DIR)/routing GPATH GRTAGS GSYMS GTAGS

full: git_subs lib default

distclean: lib_clean clean

update:
	$(MAKE) -C utl clean
	$(MAKE) -C btc clean
	$(MAKE) -C ln clean
	$(MAKE) clean
	$(MAKE) default

lib:
	$(MAKE) -C libs
	$(MAKE) -C utl
	$(MAKE) -C btc
	$(MAKE) -C ln

lib_clean:
	$(MAKE) -C libs clean
	$(MAKE) -C utl clean
	$(MAKE) -C btc clean
	$(MAKE) -C ln clean

git_subs:
	git submodule update --init --recursive

test:
	$(MAKE) -C gtest
	$(MAKE) -C utl test
	$(MAKE) -C btc test
	$(MAKE) -C ln test

test-integration:
	cd tests/4nodes_test; timeout 180 ./example_all.sh

