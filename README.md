ucoind
====

# 構成
* Ubuntu 16.04.2で動作確認中
* `ucoin` がライブラリ部、 `ucoind` が通信を含めたアプリ部
* 全体としてエラーに対応しておらず、不整合が発生したらabortする。


# dependency

## libraries

* [lmdb](https://symas.com/lightning-memory-mapped-database/)([github](https://github.com/LMDB/lmdb))
* [jansson](http://www.digip.org/jansson/)([github](https://github.com/akheron/jansson))
* [curl](https://curl.haxx.se/)([github](https://github.com/curl/curl))
* ucoin
    * [mbedTLS](https://tls.mbed.org/)([github](https://github.com/ARMmbed/mbedtls))
    * [libbase58 github](https://github.com/luke-jr/libbase58)
    * [libsodium](https://download.libsodium.org/doc/)([github](https://github.com/jedisct1/libsodium))


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
        * `dumpprivkey`


# build

* first time

        make full

* update `ucoind `or `ucoincli`

        make


* update `ucoin`

        make update

* その他
    * libs で submodule を使っているのと、`ucoin/libs` でも submodule を使っているため、取得には注意 (make fullで取得するようにしている)
    * ビルドに失敗する場合は、 `libtool` や `autoconf` のインストール状況を確認すること
        * sudo apt install build-essential libtool autoconf


# implement status

| BOLT | status |
|------|-------|
|  1   | `error` 未サポート  |
|  2   | \*1 |
|  3   | 実装はしているが、BOLT#2と連携できていない箇所あり。 |
|  4   | エラー対応していない。 |
|  5   | Mutual Close以外のclose手段を実装していない。 |
|  6   | not |
|  7   | \*2 |
|  8   | supported |
|  9   | `initial_routing_sync` = 0 のみ |

* 全体としてエラーに対応しておらず、不整合が発生したらabortする。


## BOLT#2 (\*1)
### Channel Establishment
* ほぼ実装できているつもり。


### Channel Close
* FEEは相手と同じ値を即座に返している(実際は、FEEの認識が合うまで通信し合うようになっている)。


### Normal Operation
* エラーメッセージに対応していない(abortする)。
* `commitment_signed` がなかった場合の取消にまだ対応できておらず、受信メッセージをすぐに反映させている。


### Message Retransmission
* 未確認


## BOLT#7 (\*2)
* channel作成時に `announcement_signatures` を交換後、`channel_announcement` を交換する。
* channelができている場合、init交換後に `node_announcement` を交換する。
* announcement系メッセージはチャネル間で送信するだけで、他への定期送信は行っていない。
* `channel_update` は未対応。



# 主な使い方

## 準備

1. bitcoindを動かしておく。

        例:
        testnet=3
        server=1
        txindex=1
        rpcuser=bitcoinuser
        rpcpassword=bitcoinpassword


## チャネル開始から送金まで

下のようにチャネルを開いた後、node_4444 --> node_3333 --> node_5555 という送金を行う。  
チャネルを2つ開くとき、それぞれ 10mBTC使う例になっているため、bitcoindに20mBTC以上入っていること。  
(行っている内容についてはスクリプトのコメントを参照)

        +-----------+         +-----------+         +-----------+
        | node_4444 +---------+ node_3333 +---------+ node_5555 |
        |           |         |           |         |           |
        +-----------+         +-----------+         +-----------+

1. ビルド直後の状態とする。

2. ディレクトリ移動

        $ cd install

3. ノードを立てるための設定ファイルを作成する

        $ ./example_st1.sh

4. ノードを起動する

        $ ./example_st2.sh

5. チャネルを開く  
        confirmationに時間がかかるが、"get confirmation" のログが止まるまで待つ。  
        funding_tx の TXIDは、node_4444/fund4444_3333.conf や node_5555/fund5555_3333.conf の txidからたどることになる。

        $ ./example_st3.sh

6. 送金を行う  
        送金前と送金後に、拡張子が.cnlのファイル(チャネル情報)を作るので、額はそれを比較するとよい。

        $ ./example_st4.sh

7. チャネルを閉じる
        すぐにブロックチェーンに公開するが、内部情報はブロックに取り込まれるまで保持している。  
        その前に ucoind を停止させると使えないチャネル情報が残ってしまう。  
        DBの内容は dblog.sh や dbwallet.sh などで確認できるので、不要であれば DBごと削除してもよい。

        $ ./example_st5.sh
