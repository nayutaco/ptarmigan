# ptarmigan

## バージョンアップにおける注意

* DBにバージョンが不一致の場合、起動できないようにしている。  
  その場合はディレクトリごと削除して新たに作りなおすこと(必要であれば、事前に-xでクローズすること)。

## 名前の由来

`ptarmigan` は「雷鳥」(Lightning Network→雷→雷鳥)。  

## 構成

* bitcoin testnet/regtest用
* Ubuntu 16.04.2で動作確認中

## dependency

### libraries

* git clone
  * [jansson](http://www.digip.org/jansson/)([github](https://github.com/akheron/jansson))
  * [curl](https://curl.haxx.se/)([github](https://github.com/curl/curl))
  * [jsonrpc-c(github)](https://github.com/hmng/jsonrpc-c)
  * [inih(github)](https://github.com/benhoyt/inih)
  * [mbedTLS](https://tls.mbed.org/)([github](https://github.com/ARMmbed/mbedtls))
  * [libbase58 github](https://github.com/luke-jr/libbase58)
  * [libsodium](https://download.libsodium.org/doc/)([github](https://github.com/jedisct1/libsodium))
  * [lmdb](https://symas.com/lightning-memory-mapped-database/)([github](https://github.com/LMDB/lmdb))

* install
  * [libev](http://software.schmorp.de/pkg/libev.html)
  * [boost](http://www.boost.org/)

  `sudo apt install autoconf pkg-config libev-dev libboost-all-dev`

## application

* [bitcoind](https://github.com/bitcoin/bitcoin)
  * bitcoin-cli(スクリプトでのfund-inトランザクションの送信)
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
    * `dumpprivkey` (open_channelで使用)
    * `estimatefee`

## build

* first time

        make full

* update `ucoind` or `ucoincli`

        make

* その他
  * libs で submodule を使っているため、取得には注意 (make fullで取得するようにしている)
  * ビルドに失敗する場合は、 `libtool` や `autoconf` のインストール状況を確認すること
    * `sudo apt install build-essential libtool autoconf`

## implement status

| BOLT | status |
|------|-------|
|  1   | implementing |
|  2   | implementing |
|  3   | implementing |
|  4   | implementing |
|  5   | implementing |
|  6   | (removed from BOLT) |
|  7   | almost implemated |
|  8   | supported |
|  9   | - |
|  10  | yet |
|  11  | yet |

[detail](docs/bolt_compat.md)

## 主な使い方

[install/README.md](install/README.md)参照
