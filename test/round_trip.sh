#!/bin/bash -x
set -e
lock_box=../lock_box
open_box=../open_box
KEY_FILE=`mktemp -ut round_trip.key` # -u: don't wanna create the keyfile yet
TXT_FILE=`dirname $0`/lorem.txt
BOX_FILE=`mktemp -t lorem.box`
NEW_TXT_FILE=`mktemp -t lorem.txt`
$lock_box -k $KEY_FILE < $TXT_FILE > $BOX_FILE
$open_box -k $KEY_FILE < $BOX_FILE > $NEW_TXT_FILE
diff $TXT_FILE $NEW_TXT_FILE
