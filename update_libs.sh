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

######################################################
cd libs
func_upd curl https://github.com/curl/curl.git master
func_upd jansson https://github.com/akheron/jansson.git master
func_upd jsonrpc-c https://github.com/nayutaco/jsonrpc-c.git localonly
func_upd inih https://github.com/benhoyt/inih.git master

cd ../ucoin/libs
func_upd bech32 https://github.com/nayutaco/bech32.git master
func_upd libbase58 https://github.com/luke-jr/libbase58.git master
func_upd libsodium https://github.com/jedisct1/libsodium.git master
func_upd lmdb https://github.com/LMDB/lmdb.git mdb.master
func_upd mbedtls https://github.com/ARMmbed/mbedtls.git development
