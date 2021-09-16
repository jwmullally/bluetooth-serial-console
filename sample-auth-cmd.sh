#!/bin/sh
set -e

if [ "$#" -lt 1 ]; then
	echo "Usage: $0 ADDRESS [PIN]" >&2
	exit 1
fi

ADDRESS=$1
PIN=""
if [ "$#" -ge 1 ]; then
	PIN="$2"
fi

echo "$0: ADDRESS='$ADDRESS' PIN='$2'"
echo "Returning 0 to authorize."
exit 0