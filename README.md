# ptarmigan

## 

* bitcoind v0.15
  * for bitcoin testnet/regtest (mainnet not support now)
* Ubuntu 16.04

## build

### installation

```bash
sudo apt install autoconf pkg-config libcurl4-openssl-dev libjansson-dev libev-dev libboost-all-dev build-essential libtool autoconf jq
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
git submodule update
git pull
./update_libs.sh
make full
```

### deep clean

```bash
make distclean
```

## usage

[install/README.md](install/README.md)

## dependency

### libraries

* git clone
  * [jsonrpc-c(github)](https://github.com/hmng/jsonrpc-c)
  * [inih(github)](https://github.com/benhoyt/inih)
  * [mbedTLS](https://tls.mbed.org/)([github](https://github.com/ARMmbed/mbedtls))
  * [libbase58 github](https://github.com/luke-jr/libbase58)
  * [libsodium](https://download.libsodium.org/doc/)([github](https://github.com/jedisct1/libsodium))
  * [lmdb](https://symas.com/lightning-memory-mapped-database/)([github](https://github.com/LMDB/lmdb))

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
    * `dumpprivkey` (for open_channel)
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

[detail](docs/bolt_compat.md)
