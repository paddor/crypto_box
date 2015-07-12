#!/bin/sh -x
set -e
EMPTY_FILE=`mktemp -t empty.txt.XXXXXX`
`dirname $0`/round_trip.sh $EMPTY_FILE
