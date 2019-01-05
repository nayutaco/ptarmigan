#!/bin/bash -ue

SCRIPT_NAME=$(basename $0)
SCRIPT_DIR=$(cd $(dirname $0); pwd)
PRJ_HOME=$SCRIPT_DIR/../

if [ $# -ne 2 ]; then
  echo "$SCRIPT_NAME old new" 1>&2
  exit 1
fi

(
cd $PRJ_HOME
ls \
    utl/*.[ch] \
    utl/tests/*.[ch]pp \
 \
    btc/*.[ch] \
    btc/tests/*.[ch]pp \
    btc/examples/*.[ch] \
 \
    ln/*.[ch] \
    ln/tests/*.[ch]pp \
 \
    ptarmd/*.[ch] \
    ptarmd/tests/*.[ch]pp \
    ptarmd/jni/*.[ch] \
 \
    ptarmcli/*.[ch] \
    routing/*.[ch] \
    showdb/*.[ch] \
 | grep -v bip39_wordlist_english.h \
 | xargs sed -i -e "s/$1/$2/g"
cd -
)
