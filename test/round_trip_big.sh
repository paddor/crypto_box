#!/bin/sh -x
set -e
TXT_FILE="$1"
BIG_FILE=`mktemp -t round_trip.pt.XXXXXX`
CHUNK_SIZE=65536

until [ `wc -c < $BIG_FILE` -gt $CHUNK_SIZE ]
do
	cat $TXT_FILE >> $BIG_FILE
done
`dirname $0`/round_trip.sh $BIG_FILE
