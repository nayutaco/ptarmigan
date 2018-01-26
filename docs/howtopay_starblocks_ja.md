# How to Pay starblocks/Y'alls from ptarmigan node.　（2018/01/25）

## 現在のptarmiganの開発状況と使い方 - 2018/01/25
- 開発中のためエラーが起きた場合アサーションでソフトウェアが落ちるようにしています。
- Starblocks またはY'allsへ支払いをするためには、それぞれの支払い先ノードに対してpayment channelのパスが存在しているノード(c-lightning)に接続する必要があります。　https://explorer.acinq.co/#/
に現在のtestnetに建てられているノードが表示されています。この中で接続パスを持つノードのID, IP address, port番号 が必要となります(IPアドレス非公開のノードもたくさんありますので注意)。
- P2Pネットワーク上での支払いであるためパス上のノードが全て正しく動作して初めて支払い完了します。エラーを返すノードがある場合、支払いは完了しません。またその場合のパスの再計算アルゴリズムは未実装です。（正しく支払いできるノードに接続しないと支払い実験できない)。
- ノードソフト本体は ```ucoind```です。    起動している```ucoind```の操作は```ucoincli```を使って行います。
- 同じVM上でテストネットに完全に同期している```bitcoind```が動作している必要があります。また、testnet上のbitcoinを持っている必要があります。
- ```ucoincli```コマンドラインは開発容易さを優先していて、まだユーザに分かりやすい状態にはなっていません。オプションを指定するファイルとコマンドラインからのオプションを混在して指定します。使用法として、"オプション指定ファイル生成プログラムを動かす ->  ucoincliにそのファイルとコマンドを渡す"ということを繰り返すパターンが多いです。
- ```c-lightning```を開発中のプロトコル確認の相手として使用しているため、```c-lightninng```との接続が一番安定しています。
- 現状、チャネル数は10個までに限定されています。
- 指定したlightning networkプロトコル用ポート番号 + 1が決め打ちでRPCのポート番号になります(変更できません)。
- 以下の例に従って実行した場合、```ptarmigan/install/node```　がノード情報が格納されるディレクトリになり、 ```ptarmigan/install/node/dbucoin```がデータベースとなります。```ucoinnd```ソフトウェアが落ちた場合、ここを残して ```ptarmigan/install/node```ディレクトリで```ucoind```を再実行すると同じノードとして立ち上がります。ただし再起動がうまくいかない場合は、```dbucoin```以下を削除して全く新しいノードとして実行してください。


## Starblocks または Y'allsに支払いをする全体像
- Ubuntu16のVMを起動
- bitcoindのインストール
- bitcoindのテストネットでの起動とtestnet faucetからの入金
- ptarmiganのインストール
- ucoind起動
- ucoindをテストネット上のc-lightningノードと接続する
- 接続したノードとの間にpayment channnelを張る
- starblocks もしくは Y'allsのWebから請求書(invoice)発行
- ptarmiganからinvoiceを使用して支払い
- 支払いがうまくいくとWeb画面が遷移します

## 具体的な操作方法


1. bitcoindをインストールして、testnet用 bitcoin.conf を準備する

 [vm-user]~/.bitcoin/bitcoin.conf
```text
rpcuser=bitcoinuser
rpcpassword=bitcoinpassword
server=1
txindex=1
testnet=1
```

2. bitcoindをtestnetで実行する
```bash
  bitcoid -daemon
```
3. ブロックチェーンが完全に同期するまで待つ（数時間かかります）

4. bitcoindでアドレスを生成し、そのアドレスにテストネット用のビットコインを bitcoin faucet WEBサイトから入手する
```bash
   bitcoin-cli getnewaddress
```

5. ptarmigan をインストールする
```
sudo apt-get install autoconf pkg-config libcurl4-openssl-dev libjansson-dev libev-dev libboost-all-dev build-essential libtool autoconf jq
git clone https://github.com/nayutaco/ptarmigan.git
   cd ptarmigan
   git checkout -b test refs/tags/2018-01-25

   make full
```
上記の8888はlightning networkのポート番号。rpcのポート番号は自動的に8889になる

6. Node設定を行い、ucoindを起動する
```bash
cd install
mkdir node
./create_nodeconf2.sh 8888 > node/node.conf
cd node
../ucoind node.conf
```
create_nodeconf2.shの引数はポート番号。  
node.confは適当に編集する。デフォルトではprivate nodeになる。

7. ucoindの接続先CONFファイル作成
```bash
cd install
./create_knownpeer2.sh 9735 [c-lightning node_id] [c-lightning node IP address] > peer.conf
```

8. ucoindを他のノードに接続させる
```bash
./ucoincli -c peer.conf 8889
```
8889はucoindのrpcポート番号
接続に成功すると、接続先から大量のノード情報が送信されてくる。大量にログが出るのでログが止まるまで待つ

9. ucoindが接続されていることを確認する
```bash
./ucoincli -l 8889
```
現在の接続情報が出力される

10. lightning networkで使用するために、segwit addressに
送金し、同時にpayment channnelにファンディングするtransaction作成のための情報を作る。
```bash
./fund-in2.sh 0.01 fund.txt > node/fund.conf
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
./ucoincli -l 8889
```
でノード状態を表示させる。チャネル開設できたら、statusがwait_minimum_depthからestablishedに変わる。
ただし、次の支払いを実行するには、channnelが生成されてアナウンスされる必要があり、6confirmation待つ必要がある（一時間ぐらいかかる）

13. Starblocks/Y'alls でinvoiceを作成する(rhash取得)
https://starblocks.acinq.co/#/  
https://yalls.org/  
は代表的なlightning network testnetでの支払いをデモするためのWEB。starblocksの場合、ドリンク購入ボタンを押して、checkoutボタンを押すことによって、画面にinvoiceが表示され、支払い待ち状態になる。 lntb********************.....のような長い番号がinvoice番号となる

14. ptarmiganから支払い実行
```bash
./ucoincli -l 8889
```
でノード状態を表示させ、payment channelのconfirmationの項目が6以上になっているか確認する（約１時間待つ)。6未満の場合payment channelのアナウンスがlightning networkにまだアナウンスされていないので、6以上になるまで待つ必要がある。
```bash
./ucoincli -r [invoice番号]
```
で支払い実行。支払いができた場合、webの画面が遷移する。

P2Pネットワーク上での支払いであるため、ネットワークの支払いパス上にあるノードがすべて正しく動作して初めて支払いが完了する。どれか一つがエラーを返した場合支払いは完了せず、ルートの再計算はまだ未実装である。また、プロトコル外のエラーメッセージを返した場合、ptarmiganは最初に書いたように、abortする構造に現在はしている。
