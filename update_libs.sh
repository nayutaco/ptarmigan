#!/bin/sh

func_upd() {
	if [ -d $1 ]; then
		cd $1
		git checkout $3
		git pull
		cd ..
	else
		echo "$1" not found
	fi
}

func_tag() {
	if [ -d $1 ]; then
		cd $1
		git checkout $3
		git pull
		git checkout $4
		cd ..
	else
		echo "$1" not found
	fi
}

######################################################

cd libs

git submodule sync
git submodule update --init

func_upd libbase58 https://github.com/luke-jr/libbase58.git 1cb26b5bfff6b52995a2d88a4b7e1041df589d35
func_upd libev https://github.com/enki/libev.git 93823e6ca699df195a6c7b8bfa6006ec40ee0003

func_tag inih https://github.com/benhoyt/inih.git master refs/tags/r42
func_tag lmdb https://github.com/LMDB/lmdb.git mdb.master refs/tags/LMDB_0.9.23
func_tag mbedtls https://github.com/ARMmbed/mbedtls.git master mbedtls-2.16.1
func_tag jansson https://github.com/akheron/jansson.git master refs/tags/v2.12
func_tag curl https://github.com/curl/curl.git master refs/tags/curl-7_63_0
func_tag zlib https://github.com/madler/zlib.git master refs/tags/v1.2.11
func_tag jsonrpc-c https://github.com/nayutaco/jsonrpc-c.git localonly refs/tags/localonly_r1
