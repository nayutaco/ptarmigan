# c-lightning testnet

## version

* [c-lightning](https://github.com/ElementsProject/lightning)
  * commit: 74a444eb7aa29ffca693a3ae5fed43dfdcc722e0
* [ptarmigan](https://github.com/nayutaco/ptarmigan)
  * tag: 2018-03-13
  * ptarmiganバージョンアップでDBの変更が行われた場合、DBクリーン(`rm -rf dbucoin`)が必要となる。

----

## 別PCでそれぞれのノードを起動する場合

* c-lightningのIPアドレスを `xx.xx.xx.xx`、ptarmiganのIPアドレスを `yy.yy.yy.yy`とする

### 手順

#### チャネル開設

 1. [btc]~/.bitcoin/bitcoin.conf

```text
rpcuser=bitcoinuser
rpcpassword=bitcoinpassword
server=1
txindex=1
testnet=1
```

2. [btc]bitcoind起動

```bash
bitcoind -daemon
```

3. [btc] (同期待ち)  

4. [ptarmigan]起動

```bash
cd install
mkdir node
cd node
../ucoind
```

5. [c-lightning]起動

* 過去のDBを消しておく

```bash
rm -rf ~/.lightning
```

* 起動

```bash
./lightningd/lightningd --network=testnet
```

6. [c-lightning]node_id取得

```bash
./cli/lightning-cli getinfo
```

7. [ptarm]接続先CONFファイル作成

```bash
cd install/node
../create_knownpeer.sh [c-lightning node_id] xx.xx.xx.xx > peer_cln.conf
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

```bash
../ucoincli -c peer_cln.conf
../ucoincli -c peer_cln.conf -f fund_yyyymmddhhmmss.conf
```

10. [btc]block生成待ち

1ブロックで、チャネルは生成される。

チャネルが生成されたかどうかは、`-l`の結果で`status`が`established`になることで確認できる。  
`watch`と`jq`を組み合わせて監視しても良い。

```bash
watch -n 10 "../ucoincli -l | jq '.result.client[].status'"
```

#### 送金(ptarmigan --> c-lightning)

1. [c-lightning]invoice作成

```bash
./cli/lightning-cli invoice 100000000 abc def
```

* 単位はmsatoshi。
  * `100000000msat` = `1mBTC`
  * "abc"や"def"は、今回は気にしなくて良い。
* 結果はJSON形式で得られる
  * 今回使用するinvoiceは、`"bolt11"`

2. [ptarm]送金

```bash
../ucoincli -r <BOLT11 invoice>
```

3. [ptarm]実施後のamountを確認

```bash
../showdb w | jq
```

* 成功した場合、`our_msat`が700000000、`their_msat`が100000000になる

#### 送金(c-lightning --> ptarmigan)

1. [ptarm]invoice作成

```bash
../ucoincli -i 20000
```

* 単位はmsatoshi。
  * `20000msat` = `20satoshi`

2. [c-lightning]送金

```bash
./cli/lightning-cli pay <BOLT11 invoice>
```

3. [c-lightning]実施後のamountを確認

```bash
./cli/lightning-cli listpeers | jq
```

* 成功した場合、`msatoshi_to_us`が99980000になる

----

## 同一PC上でそれぞれのノードを起動する場合

* ここではポート番号を、c-lightningは7777、ptarmiganは8888として動かす
  * ptarmiganのJSON-RPCポートは、待ち受けポート番号を+1した値になる

### 手順

#### チャネル開設

 1. [btc]~/.bitcoin/bitcoin.conf

```text
rpcuser=bitcoinuser
rpcpassword=bitcoinpassword
server=1
txindex=1
testnet=1
```

2. [btc]bitcoind起動

3. [btc] (同期待ち)  

4. [ptarm node]ucoind起動

```bash
cd install
mkdir node
cd node
../ucoind -p 8888
```

5. [c-lightning]c-lightningビルドおよび起動

* ビルド

```bash
cd "clightning/work/dir"
git clone https://github.com/ElementsProject/lightning.git
cd lightning
make
```

* 過去のDBも消しておく

```bash
rm -rf ~/.lightning
```

* 起動

```bash
./lightningd/lightningd --network=testnet --port 7777
```

6. [c-lightning]c-lightning node_id取得

```bash
./cli/lightning-cli getinfo
```

7. [ptarm]接続先CONFファイル作成

```bash
cd install/node
../create_knownpeer.sh [c-lightning node_id] 127.0.0.1 7777 > peer_cln.conf
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

```bash
../ucoincli -c peer_cln.conf 8889
../ucoincli -c peer_cln.conf -f fund_yyyymmddhhmmss.conf 8889
```

10. [btc]block生成待ち

1ブロックで、チャネルは生成される(2ノード間であればチャネル生成のみでOK)。

チャネルが生成されたかどうかは、`-l`の結果で`status`が`established`になることで確認できる。  
`watch`と`jq`を組み合わせて監視しても良い。

```bash
watch -n 10 "../ucoincli -l 8889 | jq '.result.client[].status'"
```

#### 送金(ptarmigan --> c-lightning)

1. [c-lightning]invoice作成

```bash
./cli/lightning-cli invoice 100000000 abc def
```

* 単位はmsatoshi。
  * `100000000msat` = `1mBTC`
  * "abc"や"def"は、今回は気にしなくて良い。
* 結果はJSON形式で得られる
  * 今回使用するinvoiceは、`"bolt11"`

2. [ptarm]送金

```bash
../ucoincli -r <BOLT11 invoice> 8889
```

3. [ptarm]実施後のamountを確認

```bash
../showdb w | jq
```

* 成功した場合、`our_msat`が700000000、`their_msat`が100000000になる

#### 送金(c-lightning --> ptarmigan)

1. [ptarm]invoice作成

```bash
../ucoincli -i 20000 8889
```

* 単位はmsatoshi。
  * `20000msat` = `20satoshi`

2. [c-lightning]送金

```bash
./cli/lightning-cli pay <BOLT11 invoice>
```

3. [c-lightning]実施後のamountを確認

```bash
./cli/lightning-cli listpeers | jq
```

* 成功した場合、`msatoshi_to_us`が99980000になる
