#!/usr/bin/env bash

set -ex

CMD="$1"
FILE_PREFIX="/tmp/ptcpdump"
FNAME="${FILE_PREFIX}_sub_program.pcapng"
LNAME="${FILE_PREFIX}_sub_program.log"
RNAME="${FILE_PREFIX}_sub_program.read.txt"

function test_ptcpdump() {
  timeout 30s ${CMD} -c 10 -i any ${PTCPDUMP_EXTRA_ARGS} -v --print -w "${FNAME}" \
	  -- curl -m 10 1.1.1.1 | tee "${LNAME}"

  cat "${LNAME}"
  cat "${LNAME}" | grep '/usr/bin/curl'
  cat "${LNAME}" | grep -F 'curl -m 10 1.1.1.1'
  cat "${LNAME}" | grep -F ' > 1.1.1.1.80: Flags [S],'        # SYN
  cat "${LNAME}" | grep -P '1.1.1.1.80 > .*: Flags \[S.\],'   # SYN-ACK
  cat "${LNAME}" | grep -F ' > 1.1.1.1.80: Flags [.],'        # ACK
}

function main() {
    test_ptcpdump
}

main
