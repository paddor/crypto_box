#!/bin/sh -x
set -e
TXT_FILE="$1"
BIG_FILE="big.txt"
CHUNK_SIZE=262144
touch $BIG_FILE
while [ `wc -c < $BIG_FILE` -le $CHUNK_SIZE ]
do
	cat $TXT_FILE >> $BIG_FILE
done
`dirname $0`/round_trip.sh $BIG_FILE
