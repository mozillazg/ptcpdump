#!/usr/bin/env bash

set -ex

CMD="$1"
FILE_PREFIX="/tmp/ptcpdump"
FNAME="${FILE_PREFIX}_sub_program_curl.pcapng"
LNAME="${FILE_PREFIX}_sub_program_curl.log"
RNAME="${FILE_PREFIX}_sub_program_curl.read.txt"


function test_ptcpdump() {
  timeout 30s ${CMD} -i any -v --print -w "${FNAME}"  \
	  -- curl -m 10 ubuntu.com | tee "${LNAME}"

  cat "${LNAME}"
  cat "${LNAME}" | grep '/usr/bin/curl'
  cat "${LNAME}" | grep -F '.80: Flags [.],'
}

function test_tcpdump_read() {
  which tcpdump || (apt update || true && apt install -y tcpdump)
  tcpdump -nr "${FNAME}"
  tcpdump -nr "${FNAME}" | grep -F '.80: Flags [.],'       # ACK
}

function test_ptcpdump_read() {
    EXPECT_NAME="${LNAME}.read.expect"
    sed 's/ [a-zA-Z0-9_-]\+ \(In\|Out\) / /g' "${LNAME}" > "${EXPECT_NAME}"
    timeout 30s ${CMD} -v -r "${FNAME}" > "${RNAME}"
    diff "${EXPECT_NAME}" "${RNAME}"
}


function main() {
    test_ptcpdump
    test_tcpdump_read
    test_ptcpdump_read
}

main
