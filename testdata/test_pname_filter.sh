#!/usr/bin/env bash

set -ex

CMD="$1"
FNAME="/tmp/filter_by_pname.pcapng"
LNAME="/tmp/filter_by_pname.log"


function test_ptcpdump() {
  timeout 30s ${CMD} -c 3 --pname curl -f -i any --print -w "${FNAME}" 2>&1 | tee "${LNAME}" &
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

function main() {
    test_ptcpdump
    test_tcpdump_read
}

main
