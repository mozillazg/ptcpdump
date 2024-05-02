#!/usr/bin/env bash

set -ex

CMD="$1"
FNAME="/tmp/base.pcapng"
LNAME="/tmp/base.log"


function test_ptcpdump() {
  timeout 20s ${CMD} -c 1 -i any --print -w "${FNAME}" \
    'dst host 1.1.1.1 and tcp[tcpflags] = tcp-syn' 2>&1 | tee "${LNAME}" | (read _; curl -m 10 1.1.1.1 &>/dev/null || true)

  cat "${LNAME}"
  cat "${LNAME}" | grep '/usr/bin/curl'
  cat "${LNAME}" | grep -F ' > 1.1.1.1.80: Flags [S],'   # SYN
}

function test_tcpdump_read() {
  which tcpdump || (apt update || true && apt install -y tcpdump)
  tcpdump -nr "${FNAME}"
  tcpdump -nr "${FNAME}" | grep -F ' > 1.1.1.1.80: Flags [S],'   # SYN
}

function main() {
    test_ptcpdump
    test_tcpdump_read
}

main
