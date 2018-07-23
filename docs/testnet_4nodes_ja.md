# testnet 4nodes

## version

* [c-lightning](https://github.com/ElementsProject/lightning)
  * commit: 0ba687732f4f00a8dd3bbad7a3656aff142e5866
* [eclair](https://github.com/ACINQ/eclair)
  * [Eclair v0.2-beta2]((https://github.com/ACINQ/eclair/releases/tag/v0.2-beta2))
* [lnd](https://github.com/lightningnetwork/lnd)
  * commit: 12cb35a6c9b4e9ee4f4ecb4b42a81602c7abbb37
* [ptarmigan](https://github.com/nayutaco/ptarmigan)
  * tag 2018-04-11

## bitcoind v0.16

```bash
bitcoind -daemon
```

* eclair
  * [Configuring Bitcoin Core](https://github.com/ACINQ/eclair#configuring-bitcoin-core)

## node_id取得

* `c-lightning`

```bash
./cli/lightning-cli getinfo
```

* `eclair`

```bash
./eclair-cli getinfo
```

* `lnd`

```bash
lncli --no-macaroons getinfo
```

* `ptarmigan`

```bash
../ptarmcli -l
```

## 接続先CONFファイル作成

* 接続先設定ファイルを作成する
  * `node_id`は上記で調べた値、IPアドレスはIPv4形式

```bash
../create_knownpeer.sh [c-lightning node_id] [node ip address] > peer_cln.conf
../create_knownpeer.sh [eclair node_id] [node ip address] > peer_eclr.conf
../create_knownpeer.sh [lnd node_id] [node ip address] > peer_lnd.conf
```

## 接続

```bash
../ptarmcli -c peer_cln.conf
../ptarmcli -c peer_eclr.conf
../ptarmcli -c peer_lnd.conf
```

## チャネル作成

* `ptarmigan`からそれぞれに対してチャネルを作成する
  * これ以降、`feerate_per_kw=10000`の結果を示す

```bash
../pay_fundin.sh 1000000 800000 300000
../ptarmcli -c peer_cln.conf -f fund_yyyymmddhhddss.conf
../ptarmcli -l
(statusが"wait_minimum_depth"になるのを確認する)
rm fund_yyyymmddhhddss.conf

../pay_fundin.sh 1000000 800000 400000
../ptarmcli -c peer_eclr.conf -f fund_yyyymmddhhddss.conf
../ptarmcli -l
(statusが"wait_minimum_depth"になるのを確認する)
rm fund_yyyymmddhhddss.conf

../pay_fundin.sh 1000000 800000 500000
../ptarmcli -c peer_lnd.conf -f fund_yyyymmddhhddss.conf
../ptarmcli -l
(statusが"wait_minimum_depth"になるのを確認する)
rm fund_yyyymmddhhddss.conf
```

## チャネル開設待ち

* watchコマンドで10秒間隔で監視し、3つとも"established"になるまで待つ

```bash
watch -n 10 "../ptarmcli -l | jq .result.peers[].status"
```

```text
                         +--------+
                         | eclair |
                         +---+----+
                             |400000000
                             |
                             |
                             |400000000
+-------------+        +-----+-----+          +-----+
| c-lightning +--------+ ptarmigan +----------+ lnd |
+-------------+        +-----------+          +-----+
      300000000    500000000   300000000      500000000
```

## チャネルアナウンス待ち

* watchコマンドで監視し、`channel_update` が6セット(1セット2メッセージとして、計12メッセージ)集まるのを待つ

```bash
watch -n 30 "../showdb -c | jq .channel_announcement_list[].type | grep -c channel_update"
```

## `ecliar`-->`c-lightning`の送金

* `c-lightning` : invoice作成
  * 10000000msat == 10000000satoshi

```bash
./cli/lightning-cli invoice 10000000 xxx1 yyy1
```

* `eclair`から送金

```bash
./eclair-cli send <BOLT11 invoice>
```

```text
                         +--------+
                         | eclair |
                         +---+----+
                             |389998990
                             |
                             |
                             |410001010
+-------------+        +-----+-----+          +-----+
| c-lightning +--------+ ptarmigan +----------+ lnd |
+-------------+        +-----------+          +-----+
      310000000    490000000   300000000      500000000
```

## `lnd`-->`c-lightning`の送金

* `c-lightning` : invoice作成
  * 10000000msat == 10000000satoshi

```bash
./cli/lightning-cli invoice 10000000 xxx2 yyy2
```

```bash
lncli --no-macaroons payinvoice <BOLT11 invoice>
```

```text
                         +--------+
                         | eclair |
                         +---+----+
                             |389998990
                             |
                             |
                             |410001010
+-------------+        +-----+-----+          +-----+
| c-lightning +--------+ ptarmigan +----------+ lnd |
+-------------+        +-----------+          +-----+
      320000000    480000000   310001010      489998990
```

## `lnd`-->`eclair`の送金

* `eclair` : invoice作成
  * 10000000msat == 10000satoshi

```bash
./eclair-cli receive 10000000 xxx1
```

```bash
lncli --no-macaroons payinvoice <BOLT11 invoice>
```

```text
                         +--------+
                         | eclair |
                         +---+----+
                             |399998990
                             |
                             |
                             |400001010
+-------------+        +-----+-----+          +-----+
| c-lightning +--------+ ptarmigan +----------+ lnd |
+-------------+        +-----------+          +-----+
      320000000    480000000   320002020      479997980
```

## `c-lightning`-->`eclair`の送金

* `eclair` : invoice作成
  * 10000000msat == 10000satoshi

```bash
./eclair-cli receive 10000000 xxx2
```

```bash
./cli/lightning-cli pay <BOLT11 invoice>
```

* [automatic overpay](https://github.com/ElementsProject/lightning/pull/1257)のため、c-lightningはランダムで加算したamountを送金する

```text
                         +--------+
                         | eclair |
                         +---+----+
                             |410015970
                             |
                             |
                             |389984030
+-------------+        +-----+-----+          +-----+
| c-lightning +--------+ ptarmigan +----------+ lnd |
+-------------+        +-----------+          +-----+
      309982009    490017991   320002020      479997980
```

## `c-lightning`-->`lnd`の送金

* `lnd` : invoice作成
  * 10000satoshi

```bash
lncli --no-macaroons addinvoice --amt 10000
```

```bash
./cli/lightning-cli pay <BOLT11 invoice>
```

* [automatic overpay](https://github.com/ElementsProject/lightning/pull/1257)のため、c-lightningはランダムで加算したamountを送金する

```text
                         +--------+
                         | eclair |
                         +---+----+
                             |410015970
                             |
                             |
                             |389984030
+-------------+        +-----+-----+          +-----+
| c-lightning +--------+ ptarmigan +----------+ lnd |
+-------------+        +-----------+          +-----+
      299968963    500031037   309989985      490010015
```

## `eclair`-->`lnd`の送金

* `lnd` : invoice作成
  * 10000satoshi

```bash
lncli --no-macaroons addinvoice --amt 10000
```

```bash
./eclair-cli send <BOLT11 invoice>
```

```text
                         +--------+
                         | eclair |
                         +---+----+
                             |400014960
                             |
                             |
                             |399985040
+-------------+        +-----+-----+          +-----+
| c-lightning +--------+ ptarmigan +----------+ lnd |
+-------------+        +-----------+          +-----+
      299968963    500031037   299989985      500010015
```

## チャネル閉鎖

```bash
../ptarmcli -c peer_lnd.conf -x
../ptarmcli -c peer_eclr.conf -x
../ptarmcli -c peer_cln.conf -x
```
