#!/bin/sh -x
set -e
TXT_FILE="$1"
BIG_FILE="big.txt"
touch $BIG_FILE
while [ `wc -c < $BIG_FILE` -le 262144 ]
do
	cat $TXT_FILE >> $BIG_FILE
done
`dirname $0`/round_trip.sh $BIG_FILE
