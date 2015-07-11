#!/bin/sh -x
set -e
lock_box=../lock_box
open_box=../open_box
KEY_FILE=`mktemp -ut round_trip.key.XXXXXX` # -u: don't wanna create the keyfile yet
TXT_FILE="$1"
BOX_FILE=`mktemp -t lorem.box.XXXXXX`
NEW_TXT_FILE=`mktemp -t lorem.txt.XXXXXX`
$lock_box -k $KEY_FILE < $TXT_FILE > $BOX_FILE
$open_box -k $KEY_FILE < $BOX_FILE > $NEW_TXT_FILE
diff $TXT_FILE $NEW_TXT_FILE
