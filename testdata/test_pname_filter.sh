#!/usr/bin/env bash

set -ex

CMD="$1"
FILE_PREFIX="/tmp/ptcpdump"
FNAME="${FILE_PREFIX}_filter_by_pname.pcapng"
LNAME="${FILE_PREFIX}_filter_by_pname.log"
RNAME="${FILE_PREFIX}_filter_by_pname.read.txt"


function test_ptcpdump() {
  timeout 30s ${CMD} -c 6 ${PTCPDUMP_EXTRA_ARGS} -v --pname curl -f -i any --print -w "${FNAME}"  | tee "${LNAME}" &
  sleep 10
  curl -m 10 1.1.1.1 &>/dev/null || true
  wait

  cat "${LNAME}"
  cat "${LNAME}" | grep '/usr/bin/curl'
  cat "${LNAME}" | grep -F ' > 1.1.1.1.80: Flags [S],'        # SYN
  cat "${LNAME}" | grep -F ' > 1.1.1.1.80: Flags [.],'        # ACK
}

function test_tcpdump_read() {
  which tcpdump || (apt update || true && apt install -y tcpdump)
  tcpdump -nr "${FNAME}"
  tcpdump -nr "${FNAME}" | grep -F ' > 1.1.1.1.80: Flags [S],'       # SYN
  tcpdump -nr "${FNAME}" | grep -F ' > 1.1.1.1.80: Flags [.],'       # ACK
}

function test_ptcpdump_read() {
    EXPECT_NAME="${LNAME}.read.expect"
    cat "${LNAME}" > "${EXPECT_NAME}"
    timeout 30s ${CMD} -v -r "${FNAME}" > "${RNAME}"
    cat "${RNAME}" | grep -F ' > 1.1.1.1.80: Flags [S],'        # SYN
    cat "${RNAME}" | grep -F ' > 1.1.1.1.80: Flags [.],'        # ACK
}

function main() {
    test_ptcpdump
    test_tcpdump_read
    test_ptcpdump_read
}

main
