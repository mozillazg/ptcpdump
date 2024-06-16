#!/usr/bin/env bash

set -ex

CMD="$1"
FILE_PREFIX="/tmp/ptcpdump"
FNAME="${FILE_PREFIX}_filter_by_pname.pcapng"
LNAME="${FILE_PREFIX}_filter_by_pname.log"
RNAME="${FILE_PREFIX}_filter_by_pname.read.txt"


function test_ptcpdump() {
  timeout 30s ${CMD} -c 6 -v --pname curl -f -i any --print -w "${FNAME}" --exec-events-worker-number=50 | tee "${LNAME}" &
  sleep 10
  curl -m 10 1.1.1.1 &>/dev/null || true
  wait

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
