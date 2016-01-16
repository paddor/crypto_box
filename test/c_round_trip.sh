#!/bin/sh -x
set -e
exec > c_round_trip.out 2> c_round_trip.err

# test output
echo "foobar"
#echo "foobar stderr" >&2

c_round_trip=./c_round_trip
TXT_FILE="$1"
if ! $c_round_trip $TXT_FILE
then
	exitcode=$?
	echo "$c_round_trip failed with exit code: $exitcode"
	exit 1
fi
