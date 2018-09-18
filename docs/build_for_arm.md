# build ptarmigan for Arm

## install

* cross compiler
  * [Raspberry Pi](https://github.com/raspberrypi/tools)

## configure

* `options.mak`
  * set `GNU_PREFIX`
* add your compiler path to `PATH`

## full build

```bash
make distclean
make full
```
