#!/bin/bash -ue

SCRIPT_NAME=$(basename $0)
SCRIPT_DIR=$(cd $(dirname $0); pwd)
PRJ_HOME=$SCRIPT_DIR/../..

$PRJ_HOME/tools/log_filter.sh $SCRIPT_DIR/node_*/logs/log*
