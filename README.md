# ptarmigan

## setup

* bitcoind v0.15
  * for bitcoin testnet/regtest (`ptarmigan` mainnet not support now)
* Ubuntu 16.04

## build

### installation

```bash
sudo apt install git autoconf pkg-config libcurl4-openssl-dev libjansson-dev libev-dev libboost-all-dev build-essential libtool jq
git clone https://github.com/nayutaco/ptarmigan.git
cd ptarmigan
make full
```

### update

```bash
cd ptarmigan
git pull
(make clean)
make
```

#### NOTICE

* Updating `ptarmigan` sometimes changes the version of internal DB data.  
  In that case, delete previous `dbucoin` directory(if you need close, execute `ucoincli -x`).

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

## usage (English version is underconstruction)

* [install/README.md](install/README.md) (Japanese)
* [How to Pay starblocks/Y'alls](docs/howtopay_starblocks_ja.md) (Japanese)

## dependency

### libraries

* git submodule
  * [inih](https://github.com/benhoyt/inih)
  * [libbase58](https://github.com/luke-jr/libbase58)
  * [mbedTLS](https://tls.mbed.org/) ([github](https://github.com/ARMmbed/mbedtls))
  * [libsodium](https://download.libsodium.org/doc/) ([github](https://github.com/jedisct1/libsodium))
  * [lmdb](https://symas.com/lightning-memory-mapped-database/) ([github](https://github.com/LMDB/lmdb))
  * [jsonrpc-c](https://github.com/nayutaco/jsonrpc-c) - forked from [hmng/jsonrpc-c](https://github.com/hmng/jsonrpc-c)
  * [bech32](https://github.com/nayutaco/bech32) - forked from [sipa/bech32](https://github.com/sipa/bech32)

* install
  * [curl](https://curl.haxx.se/)
  * [jansson](http://www.digip.org/jansson/)
  * [libev](http://software.schmorp.de/pkg/libev.html) (for `jsonrpc-c`)
  * [boost](http://www.boost.org/) (for dijkstra shortest paths)
  * [jq](https://stedolan.github.io/jq/) (for test scripts)

### application

* [bitcoind](https://github.com/bitcoin/bitcoin)
  * bitcoin-cli
    * `getnewaddress`
    * `addwitnessaddress`
    * `sendtoaddress`
    * `gettxout`
  * JSON-RPC
    * `getblockcount`
    * `getrawtransaction`
    * `sendrawtransaction`
    * `gettxout`
    * `getblock`
    * `getnewaddress`
    * `dumpprivkey` (for funding)
    * `estimatefee`

## implement status

| BOLT | status |
|------|-------|
|  1   | partial supported |
|  2   | partial supported |
|  3   | partial supported |
|  4   | partial supported |
|  5   | partial supported |
|  6   | (removed from BOLT) |
|  7   | almost implemated |
|  8   | supported |
|  9   | - |
|  10  | yet |
|  11  | partial supported |

[detail](docs/bolt_compat_ja.md) (Japanese)
