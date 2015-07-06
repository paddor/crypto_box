#!/bin/bash -x
set -e
lock_box=../lock_box
TXT_FILE=`dirname $0`/lorem.txt
BOX_FILE=`mktemp -t lorem.box`
$lock_box < $TXT_FILE > $BOX_FILE
(( `stat -f %z $TXT_FILE` == `stat -f %z $BOX_FILE` - 41))
