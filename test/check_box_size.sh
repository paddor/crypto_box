#!/bin/sh -x
set -e
lock_box=../lock_box
TXT_FILE=`dirname $0`/lorem.txt
BOX_FILE=`mktemp -t lorem.box.XXXXXX`
$lock_box < $TXT_FILE > $BOX_FILE
TXT_FILE_SIZE=`wc -c < $TXT_FILE`
BOX_FILE_SIZE=`wc -c < $BOX_FILE`
BOX_FILE_SIZE_SHOULD=`expr $TXT_FILE_SIZE + 41`
[ "$BOX_FILE_SIZE_SHOULD" -eq "$BOX_FILE_SIZE" ]
