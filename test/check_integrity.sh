#!/bin/sh -x
set -e

# $1 should be the path to a file that it smaller than ~64
# KiB.

NONCE_SIZE=16
CHUNK_SIZE=65536
KEY_SIZE=32

TXT_FILE="$1"
BIG_FILE=`mktemp -t integrity.pt.XXXXXX`
BOX_FILE=`mktemp -t integrity.ct.XXXXXX`
KEY_FILE=`mktemp -t integrity.key.XXXXXX`

NONCE_FILE=`mktemp -t integrity.nonce.XXXXXX`
ALL_CHUNKS_FILE=`mktemp -t integrity.all_chunks.XXXXXX`
CHUNK_FILES=`mktemp -ut integrity.chunk.XXXXXX` # template for split

head -c $KEY_SIZE /dev/random > $KEY_FILE
lock_box="../lock_box -k $KEY_FILE"
open_box="../open_box -k $KEY_FILE"

# fill up a multi-chunk plaintext file
big_file_size=0
txt_file_size=`wc -c < $TXT_FILE`
target_size=`expr $CHUNK_SIZE`
until [ $big_file_size -gt $target_size ]
do
	cat $TXT_FILE >> $BIG_FILE
	big_file_size=`expr $big_file_size + $txt_file_size`
done

# encrypt
$lock_box < $BIG_FILE > $BOX_FILE

# dissect box file
head -c $NONCE_SIZE < $BOX_FILE > $NONCE_FILE
tail -c +`expr $NONCE_SIZE + 1` < $BOX_FILE > $ALL_CHUNKS_FILE
split -a 1 -b $CHUNK_SIZE $ALL_CHUNKS_FILE ${CHUNK_FILES}.
ls -la ${CHUNK_FILES}.*

##
# TESTS

# missing nonce
if $open_box < $ALL_CHUNKS_FILE >/dev/null
then
	echo "Missing nonce undetected." >&2
	exit 1
fi

# appended chunk
APPENDED_CHUNK_FILE=`mktemp -t integrity.appended_chunk.XXXXXX`
cat $BOX_FILE >> $APPENDED_CHUNK_FILE
head -c $CHUNK_SIZE /dev/random >> $APPENDED_CHUNK_FILE
if $open_box < $APPENDED_CHUNK_FILE >/dev/null
then
	echo "Appended chunk undetected." >&2
	exit 1
fi