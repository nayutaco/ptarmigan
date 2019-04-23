# ptarmigan

[![Build Status](https://travis-ci.org/nayutaco/ptarmigan.svg?branch=development)](https://travis-ci.org/nayutaco/ptarmigan)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg?style=flat-square)
![Issue Welcome](https://img.shields.io/badge/issue-welcome-brightgreen.svg)
<!-- [![Coverity Scan Build Status](https://scan.coverity.com/projects/15128/badge.svg)](https://scan.coverity.com/projects/nayutaco-ptarmigan) -->

![Ptarmigan](docs/images/ptarmigan_text.png)

## About

* [Lightning Network BOLT](https://github.com/lightningnetwork/lightning-rfc) implementation
* In Japanese, `ptarmigan` is called "雷(thunder)鳥(bird)".

## Setup

* Ubuntu 18.04
* bitcoind
  * above v0.17(`getnetworkinfo` version > 170000)
  * for bitcoin testnet/regtest (`ptarmigan` mainnet not support now)
  * nested in BIP16 P2SH

## Install

```bash
sudo apt install -y git autoconf pkg-config build-essential libtool python3 wget jq bc

git clone https://github.com/nayutaco/ptarmigan.git
cd ptarmigan
make full
(takes a lot of time...)
```

[more...](docs/INSTALL.md)

## Starting `bitcoind`

At first, start `bitcoind`.
`ptarmd` use bitcoind JSON-RPC, so need `rpcuser` and `rpcpassword`.

* bitcoin.conf sample

```text
rpcuser=bitcoinuser
rpcpassword=bitcoinpassword
server=1
txindex=1
```

```bash
bitcoind -daemon

# check started chain
bitcoin-cli getblockchaininfo | jq -e '.chain'
```

## Starting `ptarmd`

For starting `ptarmd`, you should make new node as follows.

```bash
cd ptarmigan/install
./new_nodedir.sh [NODENAME]
cd [NODENAME]

# start ptarmigan daemon
#   CHAIN=mainnet, testnet or regtest
../ptarmd --network=[CHAIN]
```

* [NOTE](docs/INSTALL.md#NOTE)
* [How to use](docs/howtouse.md)

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
