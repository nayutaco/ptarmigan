# build ptarmd for SPV

## build

* JDK
  * Raspberry Pi2/3(Cortex-A)
    * already installed (maybe)
  * Raspberry Pi1/Zero (Arm11)
    * install `openjdk-8-jdk`

* configure

  * `options.mak`
    * set `USE_SPV=1`

* build

```bash
make clean
make
```

## execute

* configure
  * `install/jdk.sh`
    * uncomment `JDK_HOME` and `JDK_CPU`

* exec (testnet)

```bash
cd install
source jdk.sh
./new_nodedir.sh
cd node
../ptarmd -t
```
