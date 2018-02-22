# c-lightning testnet

## 前提

* c-lightning : commit b536e97df29e2881eda0bda008a3c8b1e412d249
* ここではポート番号を、c-lightningは7777、ptarmiganは8888として動かしている
  * ptarmiganのJSON-RPCポートは、待ち受けポート番号を+1した値になる

## 手順

### チャネル開設

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

5. [cln]c-lightningビルドおよび起動

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

6. [cln]c-lightning node_id取得

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

* 自分には5mBTC、相手には0でチャネルを作成
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

1ブロックで、チャネルは生成される。  
6ブロックで、channel_announcementが行われる。  

チャネルが生成されたかどうかは、`-l`の結果で`status`が`established`になることで確認できる。  
`watch`と`jq`を組み合わせて監視しても良い。

```bash
watch -n 10 "../ucoincli -l 8889 | jq '.result.client[].status'"
```

### 送金(ptarmigan --> c-lightning)

* 1confirmation以上経過していれば送金可能
  * 経過したconfirmation数は以下で取得できる
    * `../ucoincli -l 8889 | jq '.result.client[].confirmation'`

1. [cln]invoice作成

```bash
./cli/lightning-cli invoice 10000 abc def
```

* 単位はmsatoshi。  
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

* 成功した場合、`our_msat`が799990000、`their_msat`が10000になる

### 送金(c-lightning --> ptarmigan)

* 1confirmation以上経過していれば送金可能
  * 経過したconfirmation数は以下で取得できる
    * `../ucoincli -l 8889 | jq '.result.client[].confirmation'`

1. [ptarm]invoice作成

```bash
../ucoincli -i 20000 8889
```

* 単位はmsatoshi。

2. [cln]送金

```bash
./cli/lightning-cli pay <BOLT11 invoice>
```

3. [cln]実施後のamountを確認

```bash
./cli/lightning-cli listpeers | jq
```