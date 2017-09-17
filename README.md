ptarmigan
====

# バージョンアップにおける注意

* DBにバージョンが不一致の場合、起動できないようにしている。  
  その場合はディレクトリごと削除して新たに作りなおすこと(必要であれば、事前に-xでクローズすること)。


# 名前の由来

ptarmiganは「雷鳥」(Lightning Network→雷→雷鳥)。  
Thunderbirdではない。


# 構成

* bitcoin testnet/regtest用
* Ubuntu 16.04.2で動作確認中
* `ucoin` がライブラリ部、 `ucoind` が通信を含めたアプリ部
* 全体としてエラーに対応しておらず、不整合が発生したらabortする。


# dependency

## libraries

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


# build

* first time

        make full

* update `ucoind `or `ucoincli`

        make

* その他
    * libs で submodule を使っているため、取得には注意 (make fullで取得するようにしている)
    * ビルドに失敗する場合は、 `libtool` や `autoconf` のインストール状況を確認すること
        * `sudo apt install build-essential libtool autoconf`


# implement status

| BOLT | status |
|------|-------|
|  1   | can receive `error` |
|  2   | \*1 |
|  3   | 実装はしているが、BOLT#2と連携できていない箇所あり。 |
|  4   | エラー対応していない。 |
|  5   | Mutual Close以外のclose手段を実装していない。 |
|  6   | not |
|  7   | 動作確認中 |
|  8   | supported |
|  9   | `initial_routing_sync` = 0 のみ |
|  11  | yet |

* 全体としてエラーに対応しておらず、不整合が発生したら `error` を送信せずにabortする。


## BOLT#2 (\*1)
### Channel Establishment
* ほぼ実装できているつもり。


### Channel Close
* FEEは相手と同じ値を即座に返している(実際は、FEEの認識が合うまで通信し合うようになっている)。


### Normal Operation
* エラーメッセージに対応していない(abortする)。
* `commitment_signed` がなかった場合の取消にまだ対応できておらず、受信メッセージをすぐに反映させている。


### Message Retransmission
* reestablish未対応


# 主な使い方
[install/README.md](install/README.md)参照
