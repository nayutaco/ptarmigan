# use Elements

## elementsd

```bash
WORK_DIR=YOUR/WORKING/DIRECTORY

cp elements_sample.conf $WORK_DIR/elements.conf
cd $WORK_DIR
elementsd -datadir=$PWD
```

```bash
# genesis blockhash
$ elements-cli -datadir=$PWD getblockhash 0
6eefff2dcad9692ad63ab96c79ccb5c67d6a073ad2ca185d3f0a9333cdb8a609

# default asset-id
$ e-cli dumpassetlabels
{
  "bitcoin": "b4fd3d0c0f989e2571f06da93427569b702d057887ee8e0d07c0c778edeffdb5"
}
```

## ptarmd

```bash
# enable Elements
vi options.mak
----------------------------
ENABLE_ELEMENTS=0
   ↓
ENABLE_ELEMENTS=1
----------------------------

# you can specify mainchain RPC username and password
../ptarmd --network=testchain1 --bitcoinrpcuser=user --bitcoinrpcpassword=password --bitcoinrpcport=20000 --port=3333
```

## c-lightinng

```bash
git clone https://github.com/ElementsProject/lightning.git
cd lightning

(# last checked commit-id)
(git checkout fcbd11f0c5edd09a278f2bbced05595188d40b7f)

patch -p1 < PTARMIGAN_SOURCE_DIR/docs/elements_lightningd.patch
./configure
make

./lightningd/lightningd --network=testchain1 --bitcoin-rpcuser=user --bitcoin-rpcpassword=password --bitcoin-rpcport=20000 --lightning-dir=./TESTCHAIN1 --addr=0.0.0.0:33333
```
