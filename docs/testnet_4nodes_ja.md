# testnet 4nodes

## version

* [c-lightning](https://github.com/ElementsProject/lightning)
  * commit: 74a444eb7aa29ffca693a3ae5fed43dfdcc722e0
* [eclair](https://github.com/ACINQ/eclair)
  * [Eclair v0.2-alpha10]((https://github.com/ACINQ/eclair/releases/download/v0.2-alpha10/eclair-node-0.2-alpha10-0beca13.jar))
* [lnd](https://github.com/lightningnetwork/lnd)
  * commit: 45eaa70814e8f94a569bc277c52a79a5c4351c43
* [ptarmigan](https://github.com/nayutaco/ptarmigan)
  * tag 2018-03-13
  * ptarmiganバージョンアップでDBの変更が入った場合、DBクリーンが必要となる(`rm -rf dbucoin`)。

## bitcoind

* eclair + bitcoind v0.16

```bash
bitcoind -deprecatedrpc=addwitnessaddress -daemon
```

* others

```bash
bitcoind -daemon
```

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
../ucoincli -l
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
../ucoincli -c peer_cln.conf
../ucoincli -c peer_eclr.conf
../ucoincli -c peer_lnd.conf
```

## チャネル作成

* `ptarmigan`からそれぞれに対してチャネルを作成する
  * これ以降、`feerate_per_kw=10000`の結果を示す

```bash
../pay_fundin.sh 1000000 800000 300000
../ucoincli -c peer_cln.conf -f fund_yyyymmddhhddss.conf
../ucoincli -l
(statusが"wait_minimum_depth"になるのを確認する)
rm fund_yyyymmddhhddss.conf

../pay_fundin.sh 1000000 800000 400000
../ucoincli -c peer_eclr.conf -f fund_yyyymmddhhddss.conf
../ucoincli -l
(statusが"wait_minimum_depth"になるのを確認する)
rm fund_yyyymmddhhddss.conf

../pay_fundin.sh 1000000 800000 500000
../ucoincli -c peer_lnd.conf -f fund_yyyymmddhhddss.conf
../ucoincli -l
(statusが"wait_minimum_depth"になるのを確認する)
rm fund_yyyymmddhhddss.conf
```

## チャネル開設待ち

* watchコマンドで10秒間隔で監視し、3つとも"established"になるまで待つ

```bash
watch -n 10 "../ucoincli -l | jq .result.client[].status"
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

* watchコマンドで監視し、`channel_update` が6つ集まるのを待つ
  * `lnd`は`channel_update`を返すタイミングが分からないため、6confirmation後も5つになっているかもしれない

```bash
watch -n 30 "../showdb c | jq .channel_announcement_list[][].type"
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

```text
                         +--------+
                         | eclair |
                         +---+----+
                             |409998990
                             |
                             |
                             |390001010
+-------------+        +-----+-----+          +-----+
| c-lightning +--------+ ptarmigan +----------+ lnd |
+-------------+        +-----------+          +-----+
      309998990    490001010   320002020      479997980
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

```text
                         +--------+
                         | eclair |
                         +---+----+
                             |409998990
                             |
                             |
                             |390001010
+-------------+        +-----+-----+          +-----+
| c-lightning +--------+ ptarmigan +----------+ lnd |
+-------------+        +-----------+          +-----+
      299997980    500002020   310002020      489997980
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
                             |399997980
                             |
                             |
                             |400002020
+-------------+        +-----+-----+          +-----+
| c-lightning +--------+ ptarmigan +----------+ lnd |
+-------------+        +-----------+          +-----+
      299997980    500002020   300002020      499997980
```

## チャネル閉鎖

```bash
../ucoincli -c peer_lnd.conf -x
../ucoincli -c peer_eclr.conf -x
../ucoincli -c peer_cln.conf -x
```
