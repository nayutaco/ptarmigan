#!/bin/bash -ue

SCRIPT_NAME=$(basename $0)
SCRIPT_DIR=$(cd $(dirname $0); pwd)
PRJ_HOME=$SCRIPT_DIR/../

(
cd $PRJ_HOME
git fetch --all --prune
git rebase nayutaco/development
DATE=`date +%Y%m%d`
git push -f origin HEAD:work/$DATE
cd -
)
