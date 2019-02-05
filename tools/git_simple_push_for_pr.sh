#!/bin/bash -ue

SCRIPT_NAME=$(basename $0)
SCRIPT_DIR=$(cd $(dirname $0); pwd)
PRJ_HOME=$SCRIPT_DIR/../

(
cd $PRJ_HOME
DATETIME=`date +%Y%m%d%H%M%S`
git push origin work:pr/$DATETIME
cd -
)
