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

# change URL
cd inih
CNT=`git remote -v | grep -c nayutaco`
if [ $CNT -ne 0 ]; then
	git checkout master
	git remote set-url origin https://github.com/benhoyt/inih.git
	git fetch
fi
cd ..

cd lmdb
CNT=`git remote -v | grep -c nayutaco`
if [ $CNT -ne 0 ]; then
	git checkout mdb.master
	git remote set-url origin https://github.com/LMDB/lmdb.git
	git fetch
fi
cd ..

git submodule sync
git submodule update --init

func_upd jsonrpc-c https://github.com/nayutaco/jsonrpc-c.git localonly
func_upd libbase58 https://github.com/luke-jr/libbase58.git master
func_upd libev https://github.com/enki/libev.git master

func_tag inih https://github.com/benhoyt/inih.git master refs/tags/r42
func_tag lmdb https://github.com/LMDB/lmdb.git mdb.master refs/tags/LMDB_0.9.23
func_tag mbedtls https://github.com/ARMmbed/mbedtls.git development mbedtls-2.16.1
func_tag jansson https://github.com/akheron/jansson.git master refs/tags/v2.12
func_tag curl https://github.com/curl/curl.git master refs/tags/curl-7_63_0
func_tag zlib https://github.com/madler/zlib.git master refs/tags/v1.2.11

