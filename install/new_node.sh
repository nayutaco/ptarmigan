#!/bin/bash

NODEDIR=node

if [ ${#1} -gt 0 ]; then
    NODEDIR=$1
fi

if [ -d $NODEDIR ]; then
    OLDDIR=${NODEDIR}_`date +%Y%m%d%H%M%S`
    mv $NODEDIR $OLDDIR
    echo "exist \"$NODEDIR\" --> move \"$OLDDIR\""
fi

mkdir $NODEDIR
cp -ra script $NODEDIR/

echo create new node: \"$NODEDIR\"
