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
  * [ARMmbed/MbedTLS](https://github.com/ARMmbed/mbedtls)
  * [LMDB/lmdb](https://github.com/LMDB/lmdb)
  * [akheron/jansson](https://github.com/akheron/jansson)
  * [benhoyt/inih](https://github.com/benhoyt/inih)
  * [curl/curl](https://github.com/curl/curl)
  * [enki/libev](https://github.com/enki/libev)
  * [luke-jr/libbase58](https://github.com/luke-jr/libbase58)
  * [madler/zlib](https://github.com/madler/zlib)
  * [nayutaco/jsonrpc-c](https://github.com/nayutaco/jsonrpc-c) - forked from [hmng/jsonrpc-c](https://github.com/hmng/jsonrpc-c)

* download
  * [boost](http://www.boost.org/) (for dijkstra shortest paths)

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

## Security

If you find any issues regarding security,
please disclose the information by sending an (possibly encrypted) email to security at nayuta dot co.
[Our PGP key `3C95B178758342844787766AAF91183E1DCC4222`](https://pgp.mit.edu/pks/lookup?op=vindex&search=0xAF91183E1DCC4222).
