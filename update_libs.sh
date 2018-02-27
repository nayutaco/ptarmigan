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
git submodule update

cd libs
func_upd jsonrpc-c https://github.com/nayutaco/jsonrpc-c.git localonly
func_tag inih https://github.com/benhoyt/inih.git master refs/tags/r41

cd ../ucoin/libs
func_upd bech32 https://github.com/nayutaco/bech32.git ptarmigan
func_upd libbase58 https://github.com/luke-jr/libbase58.git master
func_tag libsodium https://github.com/jedisct1/libsodium.git master 1.0.16
func_tag lmdb https://github.com/LMDB/lmdb.git mdb.master LMDB_0.9.21
func_tag mbedtls https://github.com/ARMmbed/mbedtls.git development mbedtls-2.7.1
