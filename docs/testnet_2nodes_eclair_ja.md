# eclair testnet

## version

* [eclair](https://github.com/ACINQ/eclair)
  * [Eclair v0.2-alpha10]((https://github.com/ACINQ/eclair/releases/download/v0.2-alpha10/eclair-node-0.2-alpha10-0beca13.jar))
* [ptarmigan](https://github.com/nayutaco/ptarmigan)
  * tag 2018-03-13
  * ptarmiganバージョンアップでDBの変更が行われた場合、DBクリーン(`rm -rf dbucoin`)が必要となる。  

----

## 別PCでそれぞれのノードを起動する場合

* eclairのIPアドレスを `xx.xx.xx.xx`、ptarmiganのIPアドレスを `yy.yy.yy.yy`とする

### 手順

#### チャネル開設

 1. bitcoinノード設定

* [bitcoind]~/.bitcoin/bitcoin.conf

```text
rpcuser=bitcoinuser
rpcpassword=bitcoinpassword
server=1
txindex=1
testnet=1
```

* [eclair]~/.eclair/eclair.conf

```text
eclair.bitcoind.rpcuser=bitcoinuser
eclair.bitcoind.rpcpassword=bitcoinpassword
eclair.api.enabled=true
eclair.api.password=xxxxx
```

2. bitcoind起動

* eclair + bitcoind v0.16

```bash
bitcoind -deprecatedrpc=addwitnessaddress -daemon
```

* eclair + bitcoind v0.15

```bash
bitcoind -daemon
```

* ptarmigan

```bash
bitcoind -daemon
```

3. 同期待ち

4. [ptarmigan]起動

```bash
cd install
mkdir node
cd node
../ucoind
```

5. [eclair]起動

* 過去のDBを消しておく

```bash
rm ~/.eclair/eclair.log  ~/.eclair/eclair.sqlite  ~/.eclair/network.sqlite
```

* 起動
  * testnetで動かす場合、`bitcoind`にUTXOがあると、そのすべてをP2WPKH(BIP16 P2SH形式)にしておかないと[エラーになる](https://github.com/nayutaco/lightning-memo/wiki/eclair#%E3%82%A8%E3%83%A9%E3%83%BC)ようだった

```bash
java -jar eclair-node-0.2-alpha10-0beca13.jar
```

* client appをダウンロード
  * ダウンロードした`eclair-cli`は、テキストエディタで8行目辺りにある`PASSWORD`を`eclair.conf`に記載した`eclair.api.password`と同じ文字を書き込む
  * 書かなかった場合、毎回質問される

```bash
wget https://raw.githubusercontent.com/ACINQ/eclair/master/eclair-core/eclair-cli
chmod u+x eclair-cli
```

6. [eclair]node_id取得

```bash
./eclair-cli getinfo
```

7. [ptarm]接続先CONFファイル作成

```bash
cd install/node
../create_knownpeer.sh [eclair node_id] xx.xx.xx.xx > peer_eclr.conf
```

8. [ptarm]fund-in transaction作成

```bash
../pay_fundin.sh 1000000 800000 0
```

* 自分には8mBTC、相手には0でチャネルを作成
  * 1000000(`fund-in satoshi`)は、チャネルに送金する手前のアドレスに対する送金額。  
  * 800000(`channel satoshi`)は、実際にチャネルに送金する額。  
  * 0(`push satoshi`)は、`channel satoshi`のうち相手に渡す額。
* `pay_fundin.sh`は`fund_yyyymmddhhmmss.conf`という形式のファイルを作成する。

9. [ptarm]Establish開始

* eclair側の`bitcoind`がv0.16で、オプションに`-deprecatedrpc=addwitnessaddress`を指定しない場合、fundingが進まなくなる
  * `~/.eclair/eclair.log`を確認
* `feerate_per_kw`が違いすぎるというエラーが出た場合、`fund_yyyymmddhhmmss.conf`を変更する
  * 最終行に`feerate_per_kw=zzzzz`(zzzzzはエラーメッセージの`localFeeratePerKw`に近い値)を追加する

```bash
../ucoincli -c peer_eclr.conf
../ucoincli -c peer_eclr.conf -f fund_yyyymmddhhmmss.conf
```

10. [btc]block生成待ち

2ブロックで、チャネルは生成される。

チャネルが生成されたかどうかは、`-l`の結果で`status`が`established`になることで確認できる。  
`watch`と`jq`を組み合わせて監視しても良い。

```bash
watch -n 10 "../ucoincli -l | jq '.result.client[].status'"
```

#### 送金(ptarmigan --> eclair)

1. [eclair]invoice作成

```bash
./eclair-cli receive 100000000 abc
```

* 単位はmsat。
  * `100000000msat` = `1mBTC`
  * `abc`は気にしなくて良い。

2. [ptarm]送金

```bash
../ucoincli -r <BOLT11 invoice>
```

3. [ptarm]実施後のamountを確認

```bash
../showdb w | jq
```

* 成功した場合、`our_msat`が700000000、`their_msat`が100000000になる

#### 送金(eclair --> ptarmigan)

1. [ptarm]invoice作成

```bash
../ucoincli -i 20000
```

* 単位はmsatoshi。
  * `20000msat` = `20satoshi`

2. [eclair]送金

```bash
./eclair-cli send <BOLT11 invoice>
```

3. [eclair]実施後のamountを確認

```bash
./eclair-cli channels
(channelId取得)

./eclair-cli channel <channelId>
```

* 成功した場合、`balanceMsat`が99980000になる
