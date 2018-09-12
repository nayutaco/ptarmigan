# ptarmigan

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg?style=flat-square)](http://makeapullrequest.com)
[![Build Status](https://travis-ci.org/nayutaco/ptarmigan.svg?branch=development)](https://travis-ci.org/nayutaco/ptarmigan)
[![Coverity Scan Build Status](https://scan.coverity.com/projects/15128/badge.svg)](https://scan.coverity.com/projects/nayutaco-ptarmigan)

## About

* [Lightning Network BOLT](https://github.com/lightningnetwork/lightning-rfc) implementation
* In Japanese, `ptarmigan` is called "雷(thunder)鳥(bird)".
* [CHANGELOG](CHANGELOG.md)

## Setup

* bitcoind v0.16
  * for bitcoin testnet/regtest (`ptarmigan` mainnet not support now)
  * nested in BIP16 P2SH
* Ubuntu 16.04

## Usage

* [docs/README.md](docs/README.md)

## Build

### installation

```bash
sudo apt install -y git autoconf pkg-config build-essential libtool wget jq bc
git clone https://github.com/nayutaco/ptarmigan.git
cd ptarmigan
make full
(takes a lot of time...)
```

### update

```bash
cd ptarmigan
git pull
(make clean)
make
```

#### after change DB version

* Updating `ptarmigan` sometimes changes the version of internal DB data.  
  In that case, delete previous `dbptarm` directory(if you need close, execute `ptarmcli -x`).

### update libraries

```bash
cd ptarmigan
git pull
make full
```

### deep clean

```bash
make distclean
```

## Dependency

### libraries

* git submodule
  * [libbase58](https://github.com/luke-jr/libbase58)
  * [Mbed TLS](https://tls.mbed.org/) ([github](https://github.com/ARMmbed/mbedtls))
  * [curl](https://curl.haxx.se/)
  * [jansson](http://www.digip.org/jansson/)
  * [libev](http://software.schmorp.de/pkg/libev.html) (for `jsonrpc-c`)
  * [boost](http://www.boost.org/) (for dijkstra shortest paths)
  * [nayutaco/inih](https://github.com/nayutaco/inih) - forked from [benhoyt/inih](https://github.com/benhoyt/inih)
  * [nayutaco/lmdb](https://github.com/nayutaco/lmdb) - forked from [LMDB/lmdb](https://github.com/LMDB/lmdb)
  * [nayutaco/jsonrpc-c](https://github.com/nayutaco/jsonrpc-c) - forked from [hmng/jsonrpc-c](https://github.com/hmng/jsonrpc-c)

* install
  * [jq](https://stedolan.github.io/jq/) (for test scripts)

* reference code
  * [sipa/bech32](https://github.com/sipa/bech32)

### application

* [bitcoind](https://github.com/bitcoin/bitcoin)
  * bitcoin-cli
    * `getnewaddress`
    * `sendtoaddress`
    * `gettxout`
  * JSON-RPC
    * `getblockcount`
    * `getrawtransaction`
    * `signrawtransaction`
    * `sendrawtransaction`
    * `gettxout`
    * `getblock`
    * `getnewaddress`
    * `estimatesmartfee`
