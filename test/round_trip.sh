#!/bin/bash -x
set -e
lock_box=../lock_box
open_box=../open_box
KEY_FILE=round_trip.key
TXT_FILE=../../../tests/lorem.txt
BOX_FILE=lorem.box
NEW_TXT_FILE=lorem.txt
$lock_box -k $KEY_FILE < $TXT_FILE > $BOX_FILE
$open_box -k $KEY_FILE < $BOX_FILE > $NEW_TXT_FILE
diff $TXT_FILE $NEW_TXT_FILE
