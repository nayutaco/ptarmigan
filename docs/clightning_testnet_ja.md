# c-lightning testnet

* ここではポート番号を、c-lightningは9735、ptarmiganは8888として動かしている
  * ptarmiganのJSON-RPCポートは、待ち受けポート番号を+1した値

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

5. [cln]c-lightning起動

```bash
cd "to/clightning/dir"
./lightningd/lightningd --network=testnet --log-level=debug
```

6. [cln]c-lightning node_id取得

```bash
./cli/lightning-cli getinfo
```

7. [ptarm]接続先CONFファイル作成

```bash
cd install
./create_knownpeer.sh [c-lightning node_id] [c-lightning node IP address] > peer.conf
```

8. [ptarm]fund-in transaction作成

```bash
./fund-in.sh 0.01 fund.txt > node/fund.conf
```

0.01BTCのsegwit transactionを作成し、そこからchannelにfund.txtの配分でデポジットする。  
`funding_sat` が 0.01BTCのうちchannelにデポジットする全satoshi。  
`push_sat` が `funding_sat` のうち相手の持ち分とするsatoshi。

9. [ptarm]Establish開始

```bash
./ucoincli -c peer.conf 8889
./ucoincli -c peer.conf -f node/fund.conf 8889
```

10. [btc]block生成待ち

1ブロックで、チャネルは生成される。  
6ブロックで、announcementが行われる。  

11. [cln]invoice作成(rhash取得)

```bash
./cli/lightning-cli invoice 10000 abc def
```

単位はmsatoshi。

12. [ptarm]送金

```bash
./ucoincli -r <BOLT11 invoice> 8889
```

13. [ptarm]実施後のamountを確認

```bash
./showdb w node/dbucoin | jq
```

14. [ptarm]ptarmigan node_id取得

```bash
./ucoincli -l 8889 | jq
```

15. [ptarm]invoice作成

```bash
./ucoincli -i 20000 8889
```

16. [cln]現在のamountを確認

```bash
./cli/lightning-cli listpeers | jq
```

17. [cln]送金

```bash
./cli/lightning-cli pay <BOLT11 invoice>
```

18. [cln]実施後のamountを確認

```bash
./cli/lightning-cli listpeers | jq
```