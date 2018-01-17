# c-lightning testnet

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
./create_nodeconf2.sh 8888 > node/node.conf
cd node
../ucoind node.conf
```

create_nodeconf2.shの引数はポート番号。  
node.confは適当に編集する。デフォルトではprivate nodeになる。

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
./create_knownpeer2.sh 9735 [c-lightning node_id] [c-lightning node IP address] > peer.conf
```

8. [ptarm]fund-in transaction作成

```bash
./fund-in2.sh 0.01 fund.txt > node/fund.conf
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
c-lightningから送金する場合は、6ブロック待たないといけないかもしれない。

11. [cln]invoice作成(rhash取得)

```bash
./cli/lightning-cli invoice 10000 abc def
```

単位はmsatoshi。

12. [ptarm]送金ルート準備

```bash
./routing testnet node/dbucoin `./ucoind node/node.conf id` [c-lightning node_id] 10000 > node/pay.conf
```

13. [ptarm]現在のamountを確認

```bash
./showdb testnet w node/dbucoin
```

14. [ptarm]送金

```bash
./ucoincli -p node/pay.conf,[c-lightning rhash] 8889
```

15. [ptarm]実施後のamountを確認

```bash
./showdb testnet w node/dbucoin
```

16. [ptarm]ptarmigan node_id取得

```bash
./ucoincli -l 8889
```

17. [ptarm]invoice作成

```bash
./ucoincli -i 20000 8889
```

18. [cln]送金ルート準備

```bash
route=$(cli/lightning-cli getroute [ptarmigan node_id] 20000 1 | jq --raw-output .route -)
echo $route
```

19. [cln]現在のamountを確認

```bash
./cli/lightning-cli getpeers | jq
```

20. [cln]送金

```bash
./cli/lightning-cli sendpay "$route" [ptarmigan hash]
```

21. [cln]実施後のamountを確認

```bash
./cli/lightning-cli getpeers
```