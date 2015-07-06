#!/bin/bash -x
set -e
lock_box=../lock_box
TXT_FILE=`dirname $0`/lorem.txt
BOX_FILE=`mktemp -t lorem.box.XXX`
$lock_box < $TXT_FILE > $BOX_FILE
(( `wc -c < $TXT_FILE` == `wc -c < $BOX_FILE` - 41))
