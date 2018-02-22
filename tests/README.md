# Examples

## 準備

1. bitcoindをインストールしておく。  
  * regtestで動かすところからスクリプトにしているので、起動しておく必要はない。

## チャネル開始から送金まで (4nodes)

下のようにチャネルを開いた後、node_4444 --> node_3333 --> node_5555 --> node_6666 という送金を行う。  
チャネルを2つ開くとき、それぞれ 10mBTC使う例になっているため、bitcoindに30mBTC以上入っていること。  
(行っている内容についてはスクリプトのコメントを参照)

```text
+-----------+         +-----------+         +-----------+         +-----------+
| node_4444 +---------+ node_3333 +---------+ node_5555 |---------+ node_6666 |
|           |         |           |         |           |         |           |
+-----------+         +-----------+         +-----------+         +-----------+
```

1. ビルド直後の状態とする。  
        bitcoindは `example_st1.sh` で起動するため、立ち上げは不要(regtest)。  
        前回exampleを動かしたのであれば、 `clean.sh` を実行してファイルを削除しておくこと。

2. ディレクトリ移動

```bash
cd install
```

3. ノードを立てるための設定ファイルを作成する  
        ここで `bitcoind` の起動を行っている。

```bash
./example_st1.sh
```

4. ノードを起動する

```bash
./example_st2.sh
```

5. チャネルを開く  
        チャネルが開かれるまでスクリプトはポーリングでチェックしている。

```bash
./example_st3.sh
```

6. 送金を行う  
        送金前と送金後に、拡張子が.cnlのファイル(チャネル情報)を作るので、額はそれを比較するとよい。

```bash
./example_st4.sh
```

7. チャネルを閉じる  
        すぐにブロックチェーンに公開するが、内部情報はブロックに取り込まれるまで保持している。  
        その前に ucoind を停止させると使えないチャネル情報が残ってしまう。  
        `example_st1.sh` で起動した `bitcoind` を停止する処理も行っている。

```bash
./example_st5.sh
```

8. 不要ファイル削除  
        いくつか処理で使用したファイルが残っているので、気になるのであれば `clean.sh` を実行して削除する。

----

## ファイルの概要

### スクリプトファイル

| filename | 概要 |
|----------|------|
| `clean.sh` | (example用) `bitcoind` 停止、一時ファイル削除 |
| `default_conf.sh` | `ucoind` が読込む設定ファイルをデフォルト値で作成 |
| `example_st_conn.sh` | (example用) チャネル作成済みの `ucoind` を起動して再接続する |
| `example_st_quit.sh` | (example用) 起動している `ucoind` を終了させる |
| `example_st1.sh` | (example用) `bitcoind` 起動 |
| `example_st2.sh` | (example用) 各node作成および `ucoind` 起動 |
| `example_st3.sh` | (example用) fundingおよびチャネル情報交換完了待ち |
| `example_st4a.sh` | (example用) 送金実施 |
| `example_st4b.sh` | (example用) 送金実施 |
| `example_st4c.sh` | (example用) 送金実施 |
| `example_st4d.sh` | (example用) 送金実施 |
| `example_st4_fail1.sh` | (example用) 送金失敗(node_4444 --> node_6666 の送金直前にnode_5555を終了) |
| `example_st4_fail2.sh` | (example用) 送金失敗(invoiceと送金額を不一致にさせる) |
| `example_st4_fail2.sh` | (example用) 送金失敗(payment_hash不一致) |
| `example_st4r.sh` | (example用) 送金実施スクリプト |
| `example_st4p.sh` | (example用) 送金実施スクリプト |
| `example_st5.sh` | (example用) mutual closeおよび `bitcoind` 停止 |
| `fund-test-in.sh` | (example用) funding_txの inputとなる P2WPKHトランザクションへの送金 |
| `pay_funding.sh` | funding_txの inputとなる P2WPKHトランザクションへの送金 |

### その他ファイル

| filename | 概要 |
|----------|------|
| `script/` | `ucoind` がイベント時に実行するスクリプトファイル。 `ucoind` と同じ場所にフォルダごとコピーし、ファイルの中身は適当に編集する想定。 |
| `regtest.conf` | (example用) `bitcoind` 用設定ファイル。 `example_st1.sh` で使用する。 |
