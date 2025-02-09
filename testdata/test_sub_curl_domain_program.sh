#!/usr/bin/env bash

set -ex

CMD="$1"
FILE_PREFIX="/tmp/ptcpdump"
FNAME="${FILE_PREFIX}_sub_program_curl.pcapng"
LNAME="${FILE_PREFIX}_sub_program_curl.log"
RNAME="${FILE_PREFIX}_sub_program_curl.read.txt"


function test_ptcpdump() {
  timeout 60s ${CMD} -i any ${PTCPDUMP_EXTRA_ARGS} -v --print -w "${FNAME}"  \
	  -- curl -m 10 ubuntu.com | tee "${LNAME}"

  cat "${LNAME}"
  cat "${LNAME}" | grep '/usr/bin/curl'
  cat "${LNAME}" | grep -F '.80: Flags [S],'
  cat "${LNAME}" | grep -F 'curl -m 10 ubuntu.com'
}

function main() {
    test_ptcpdump
}

main
