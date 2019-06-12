# Testing Ptarmigan with BTCPayServer.Lightning.

Perform the following test using [BTCPayServer.Lightning] (https://github.com/btcapayserver/BTCPayServer.Lightning).

`` `
1. BTCPayServer.Lightning Ptarmigan operation check
2. Ptarmigan, LND, c-lightning, Eclair interconnection test
`` `

## 1. About BTCPayServer.Lightning Ptarmigan operation check

Ptarmigan is currently refactoring for further stabilization.

The refactoring also includes destructive things.

It is not good that the latest Ptarmigan does not work with BTCPayServer.Lightning.

In order for the latest Ptarmigan to work stably on BTCPayServer.Lightning, we have made it simultaneously check the operation on BTCPayServer.Lightning.

## 2. About Ptarmigan, LND, clightning, Eclair interconnection test

Test interconnection of Ptarmigan, LND, clightning, Eclair using BTCPayServer.Lightning.

## About Divide Travis CI and Circle CI

Since the tests performed by each CI are largely different, We decided to divide them.

Travis CI tests Ptarmigan alone, and Circle CI tests BTCPayServer.Lightning.

# BTCPayServer.Lightningを用いたPtarmiganのテスト

[BTCPayServer.Lightning](https://github.com/btcpayserver/BTCPayServer.Lightning)を用いて以下のテストを行ってます。

```
1.  BTCPayServer.LightningのPtarmigan動作確認
2.  Ptarmigan, LND, clightning, Eclairの相互接続テスト
```

## 1. BTCPayServer.LightningのPtarmigan動作確認について

Ptarmiganは、現在、さらなる安定化のためにリファクタリングを続けています。

そのリファクタリングには、破壊的なものも含まれております。

最新のPtarmiganがBTCPayServer.Lightningで動かないのは、よくありません。

常に最新のPtarmiganがBTCPayServer.Lightningで安定して動くために、BTCPayServer.Lightning上での動作確認を同時に実行するようにしました。

## 2.  Ptarmigan, LND, clightning, Eclairの相互接続テスト

BTCPayServer.Lightningを用いて、Ptarmigan, LND, clightning, Eclairの相互接続テストをします。

## Travis CIとCircle CIに分けている理由

各CIで行っているテストが大きく違うので、分けることにしました。

Travis CIでは、Ptarmigan単体のテストを行い、Circle CIでは、BTCPayServer.Lightningを用いたテストを行うようにしています。