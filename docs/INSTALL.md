# INSTALL

## NOTE

* `ptarmd` can't start if database file version not match.
  * Ptarmigan sometime changes database structure and update file version.
  * There are two ways:
    * A: pay all BTC to `bitcoind` and create new database file.
      * Close all channels and return BTC using `ptarmcli --paytowallet`.
    * B: Use previous version `ptarmd` if you use same database file.

## bitcoind version

### Ubuntu 18.04

#### first time

```bash
sudo apt install -y git autoconf pkg-config build-essential libtool python3 wget jq bc

git clone https://github.com/nayutaco/ptarmigan.git
cd ptarmigan
make full
(takes a lot of time...)
```

#### update

```bash
cd ptarmigan
git pull
make
```

[Please be careful about update](#NOTE)

#### update libraries

```bash
cd ptarmigan
git pull
./update_libs.sh
make full
```

#### clean

```bash
cd ptarmigan
make clean
```

#### deep clean

```bash
cd ptarmigan
make distclean
```