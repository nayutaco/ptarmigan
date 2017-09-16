Examples
====

# 準備

1. bitcoindを動かしておく。

        例:
        regtest=1
        server=1
        txindex=1
        rpcuser=bitcoinuser
        rpcpassword=bitcoinpassword


# チャネル開始から送金まで

下のようにチャネルを開いた後、node_4444 --> node_3333 --> node_5555 という送金を行う。  
チャネルを2つ開くとき、それぞれ 10mBTC使う例になっているため、bitcoindに20mBTC以上入っていること。  
(行っている内容についてはスクリプトのコメントを参照)

        +-----------+         +-----------+         +-----------+
        | node_4444 +---------+ node_3333 +---------+ node_5555 |
        |           |         |           |         |           |
        +-----------+         +-----------+         +-----------+

1. ビルド直後の状態とする。  
    `bitcoin-cli generate 432` などとしてsegwitが使用できるところまでマイニングしておく

2. ディレクトリ移動

        $ cd install

3. ノードを立てるための設定ファイルを作成する

        $ ./example_st1.sh

4. ノードを起動する

        $ ./example_st2.sh

5. チャネルを開く  
        confirmationに時間がかかるが、"get confirmation" のログが止まるまで待つ。  
        `regtest` では自動でマイニングされないので、 `bitcoin-cli generate 2` など行う。  
        funding_tx の TXIDは、node_4444/fund4444_3333.conf や node_5555/fund5555_3333.conf の txidからたどることになる。

        $ ./example_st3.sh

6. 送金を行う  
        送金前と送金後に、拡張子が.cnlのファイル(チャネル情報)を作るので、額はそれを比較するとよい。

        $ ./example_st4.sh

7. チャネルを閉じる
        すぐにブロックチェーンに公開するが、内部情報はブロックに取り込まれるまで保持している。  
        その前に ucoind を停止させると使えないチャネル情報が残ってしまう。  
        DBの内容は dblog.sh や dbwallet.sh などで確認できるので、不要であれば DBごと削除してもよい。

        $ ./example_st5.sh
