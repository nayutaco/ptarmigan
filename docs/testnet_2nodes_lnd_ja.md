# lnd testnet

## version

* [lnd](https://github.com/lightningnetwork/lnd)
  * commit: 45eaa70814e8f94a569bc277c52a79a5c4351c43
* [ptarmigan](https://github.com/nayutaco/ptarmigan)
  * tag: 2018-03-13
  * ptarmiganバージョンアップでDBの変更が行われた場合、DBクリーン(`rm -rf dbucoin`)が必要となる。

----

## 別PCでそれぞれのノードを起動する場合

* lndのIPアドレスを `xx.xx.xx.xx`、ptarmiganのIPアドレスを `yy.yy.yy.yy`とする

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

* [btcd]~/.btcd/btcd.conf

```text
testnet=1
txindex=1
rpcuser=nayuta
rpcpass=nayuta
```

* [btcd]~/.btcctl/btcctl.conf

```text
rpcuser=nayuta
rpcpass=nayuta
```

* [lnd]~/.lnd/lnd.conf

```text
[Application Options]
debughtlc=true
maxpendingchannels=10
no-macaroons=true
debuglevel=trace
nobootstrap=1

[Bitcoin]
bitcoin.active=1
bitcoin.testnet=1
bitcoin.node=btcd
```

2. bitcoind/btcd起動

```bash
bitcoind -daemon
```

```bash
btcd&
```

3. 同期待ち

4. [ptarmigan]起動

```bash
cd install
mkdir node
cd node
../ucoind
```

5. [lnd]起動

* 過去のDBを消しておく

```bash
rm -rf ~/.lnd/data
```

* 起動

```bash
lnd --no-macaroons
```

* wallet作成
  * 2回目以降は `lncli --no-macaroons unlock` でよい

```bash
lncli --no-macaroons create
```

6. [lnd]node_id取得

```bash
lncli --no-macaroons getinfo
```

7. [ptarm]接続先CONFファイル作成

```bash
cd install/node
../create_knownpeer.sh [lnd node_id] xx.xx.xx.xx > peer_lnd.conf
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
../ucoincli -c peer_lnd.conf
../ucoincli -c peer_lnd.conf -f fund_yyyymmddhhmmss.conf
```

10. [btc]block生成待ち

3ブロックで、チャネルは生成される。

チャネルが生成されたかどうかは、`-l`の結果で`status`が`established`になることで確認できる。  
`watch`と`jq`を組み合わせて監視しても良い。

```bash
watch -n 10 "../ucoincli -l | jq '.result.client[].status'"
```

#### 送金(ptarmigan --> lnd)

1. [lnd]invoice作成

```bash
lncli --no-macaroons addinvoice --amt 100000
```

* 単位はsatoshi。
  * `100000satoshi` = `1mBTC`

2. [ptarm]送金

```bash
../ucoincli -r <BOLT11 invoice>
```

3. [ptarm]実施後のamountを確認

```bash
../showdb w | jq
```

* 成功した場合、`our_msat`が700000000、`their_msat`が100000000になる

#### 送金(lnd --> ptarmigan)

1. [ptarm]invoice作成

```bash
../ucoincli -i 20000
```

* 単位はmsatoshi。
  * `20000msat` = `20satoshi`

2. [lnd]送金

```bash
lncli --no-macaroons payinvoice <BOLT11 invoice>
```

3. [lnd]実施後のamountを確認

```bash
lncli --no-macaroons listchannels
```

* 成功した場合、`local_balance`が99980になる
