#!/usr/bin/env bash

set -ex

CMD="$1"
FILE_PREFIX="/tmp/ptcpdump"
FNAME="${FILE_PREFIX}_sub_program.pcapng"
LNAME="${FILE_PREFIX}_sub_program.log"
RNAME="${FILE_PREFIX}_sub_program.read.txt"


function test_ptcpdump() {
  timeout 30s ${CMD} -c 10 -i any -v --print -w "${FNAME}" \
	  -- curl -m 10 1.1.1.1 | tee "${LNAME}"

  cat "${LNAME}"
  cat "${LNAME}" | grep '/usr/bin/curl'
  cat "${LNAME}" | grep -F ' > 1.1.1.1.80: Flags [S],'        # SYN
  cat "${LNAME}" | grep -P '1.1.1.1.80 > .*: Flags \[S.\],'   # SYN-ACK
  cat "${LNAME}" | grep -F ' > 1.1.1.1.80: Flags [.],'        # ACK
}

function test_tcpdump_read() {
  which tcpdump || (apt update || true && apt install -y tcpdump)
  tcpdump -nr "${FNAME}"
  tcpdump -nr "${FNAME}" | grep -F ' > 1.1.1.1.80: Flags [S],'       # SYN
  tcpdump -nr "${FNAME}" | grep -P '1.1.1.1.80 > .*: Flags \[S.\],'  # SYN-ACK
  tcpdump -nr "${FNAME}" | grep -F ' > 1.1.1.1.80: Flags [.],'       # ACK
}

function test_ptcpdump_read() {
    EXPECT_NAME="${LNAME}.read.expect"
    cat "${LNAME}" > "${EXPECT_NAME}"
    timeout 30s ${CMD} -v -r "${FNAME}" > "${RNAME}"
    diff "${EXPECT_NAME}" "${RNAME}"
}


function main() {
    test_ptcpdump
    test_tcpdump_read
    test_ptcpdump_read
}

main
