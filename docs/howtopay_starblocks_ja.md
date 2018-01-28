# How to Pay starblocks/Y'alls (or Your lightning Node) from ptarmigan node

## 現在のptarmiganの開発状況と使い方

### 2018/01/28

- プロトコル上でエラーが起きた場合、アプリケーション`ucoind`をAssertionで異常終了する場合がある。
- 送金先ノードへ支払いをするためには、送金パスが存在する必要がある。  
  [Lightning Network Explorer(TESTNET)](https://explorer.acinq.co/#/)に、testnet上に"見えている"ノードが表示されてる。  
  Lightning Networkのチャネルを接続するためには、この中で動作しているノードのID, IP address, port番号 が必要となる(IPアドレス非公開や、運用を取りやめたノードも見受けられる)。
- Lightning NetworkはP2Pネットワーク上で支払いを行うため、送金が完了するためには送金パス上が全てのノードが正しく動作する必要がある。  
  エラーを返すノードがある場合、支払いは完了しない。  
  またその場合のパスの再計算アルゴリズムは未実装（正しく支払いできるノードに接続しないと支払い実験できない)。
- ノードソフト本体は `ucoind`で、起動している `ucoind` への操作は `ucoincli` を使用する。
- `ucoind` が起動している同じlocalhost上でテストネットに完全に同期している`bitcoind`が動作している必要がある。  
  また、testnet上のbitcoinを持っている必要がある。
- `ucoincli`コマンドラインは、開発速度を優先してユーザには分かりづらいところがあり、改善していく予定である。  
  オプションを指定するファイルとコマンドラインからのオプションを混在して指定する。  
  使用法として、"オプション指定ファイル生成プログラムを動かす ->  ucoincliにそのファイルとコマンドを渡す"というパターンが多い。
- 現状、同時接続できる数は10個(開いてからの接続10個、自分からの接続10個)までに限定されている。
- 指定したlightning networkプロトコル用ポート番号 + 1が固定でJSON-RPCのポート番号になる(`ucoincli`もJSON-RPCのポートを使用する)。
- 以下の手順に従って実行した場合、`ptarmigan/install/node`　がノード情報が格納されるディレクトリになり、 `ptarmigan/install/node/dbucoin`がデータベースとなる。  
  `ucoinnd`ソフトウェアを終了した場合でも、`ptarmigan/install/node`ディレクトリで`ucoind`を再実行すると同じノードとして立ち上がる。  
  もし再起動がうまくいかない場合、`dbucoin`ディレクトリを削除して、新しいノードとして実行すること(node.confファイルを変更しない場合、ノードIDは変更されない)。

## Starblocks または Y'allsに支払いをする全体像

- Ubuntu16起動
- bitcoindのインストール
- bitcoindのテストネットでの起動とtestnet faucetからの入金
- ptarmiganのインストール
- ucoind起動
- ucoindをテストネット上のc-lightningノードと接続する
- 接続したノードとの間にpayment channnelを張る
- starblocks もしくは Y'allsのWebから請求書(invoice)発行
- ptarmiganからinvoiceを使用して支払い
- 支払いがうまくいくとWeb画面が遷移する

## 具体的な操作方法

1. bitcoindをインストールして、testnet用 bitcoin.conf を準備する

~/.bitcoin/bitcoin.conf

```text
rpcuser=bitcoinuser
rpcpassword=bitcoinpassword
server=1
txindex=1
testnet=1
```

`rpcuser`と`rpcpassword`は何でもよいが、内部で`bitcoind`を操作するため、設定はすること。

2. bitcoindをtestnetで実行する

```bash
bitcoid -daemon
```

3. ブロックチェーンが完全に同期するまで待つ（数時間かかる）

4. bitcoindでアドレスを生成し、そのアドレスにtestnet用のビットコインを bitcoin faucet WEBサイトから入手する

```bash
bitcoin-cli getnewaddress
```

5. ptarmigan をインストールする

```bash
sudo apt-get install autoconf pkg-config libcurl4-openssl-dev libjansson-dev libev-dev libboost-all-dev build-essential libtool autoconf jq
git clone https://github.com/nayutaco/ptarmigan.git
cd ptarmigan
git checkout -b test refs/tags/2018-01-28
make full
```

上記の8888はlightning networkのポート番号。  
`ucoincli`などで使用するJSON-RPCのポート番号は自動的に8889になる。

6. Node設定を行い、ucoindを起動する

```bash
cd install
mkdir node
./create_nodeconf.sh 8888 > node/node.conf
cd node
../ucoind node.conf
```

create_nodeconf.shの引数はポート番号。  
node.confは[説明](ucoind_ja.md)を見て適当に編集する(編集しなくてもよい)。  
デフォルトではprivate nodeになり、IPアドレスをアナウンスしない。
`ucoind`はdaemonとして起動するため、これ以降はUbuntuで別のコンソールを開き、そちらで作業する。

7. ucoindの接続先CONFファイル作成

```bash
cd ptarmigan/install
./create_knownpeer.sh [c-lightning node_id] [c-lightning node IP address] [c-lightning node port] > peer.conf
```

8. ucoindを他のノードに接続する

```bash
./ucoincli -c peer.conf 8889
```

8889はucoindのJSON-RPCポート番号。
接続に成功すると、`ucoind`を起動しているコンソールに接続先から大量のノード情報が出力される。  
大量にログが出るのでログが止まるまで待つ。

9. ucoindが接続されていることを確認する

```bash
./ucoincli -l 8889 | jq
```

現在の接続情報が出力される。

10. lightning networkで使用するために、segwit addressに送金し、同時にpayment channnelにファンディングするtransaction作成のための情報を作る

```bash
./fund-in.sh 0.01 fund.txt > node/fund.conf
```

0.01BTCのsegwit transactionを作成し送金。そこからchannelにfund.txtの配分でデポジットするための情報をつくる。  
`funding_sat` が 0.01BTCのうちchannelにデポジットする全satoshi。  
`push_sat` が `funding_sat` のうち相手の持ち分とするsatoshi。

11. payment channelへのファンディングを実行する

```bash
./ucoincli -c peer.conf -f node/fund.conf 8889
```

12. funding transactionnがブロックチェーンのブロックに入るのを待つ

```bash
./ucoincli -l 8889 | jq
```

ノード状態を表示させる。チャネル開設できたら、statusが `wait_minimum_depth` から `established` になる。
ただし、以降の支払いを実行するには、channnelが生成されてアナウンスされる必要があり、6confirmation待つ必要がある（1時間ぐらいかかる）。

13. Starblocks/Y'alls でinvoiceを作成する(rhash取得)

代表的なlightning network testnetでの支払いをデモするためのWEBとして、以下がある。

- [starblocks](https://starblocks.acinq.co/#/)
- [Y'alls](https://yalls.org/)

starblocksの場合、ドリンク購入ボタンを押して、checkoutボタンを押すことによって、画面にinvoiceが表示され、支払い待ち状態になる。  
`lntb********************.....` のような長い文字列がinvoice番号となる。  
支払後は自動的にWEBサイトが切り替わるため、表示させたままにしておく。

14. ptarmiganから支払い実行

```bash
./ucoincli -l 8889 | jq
```

ノード状態を表示し、payment channelのconfirmationの項目が6以上になっているか確認する（約1時間待つ)。  
6未満の場合payment channelのアナウンスをlightning networkに行っていないので、6以上になるまで待つ必要がある。

```bash
./ucoincli -r [invoice番号] 8889
```

支払い実行。  
支払いができた場合、starblocksのWEB画面が遷移する。

P2Pネットワーク上での支払いであるため、ネットワークの支払いパス上にあるノードがすべて正しく動作して初めて支払いが完了する。  
どれか一つがエラーを返した場合、支払いは完了しない。  
別のルートで送金することで成功する可能性があるが、`ptarmigan`のルート再計算機能はまだ未実装である。  
