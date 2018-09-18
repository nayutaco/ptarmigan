# build ptarmd for JNI shared library

## install

* JDK

## configure

* `options.mak`
  * set `BUILD_PTARMD=LIB`
  * set `BUILD_PTARMD_LIB_INCPATHS` your JDK include path

## full build

```bash
make distclean
make full
```
