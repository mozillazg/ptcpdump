#!/usr/bin/env bash

set -ex

CMD="$1"
FILE_PREFIX="/tmp/ptcpdump"
FNAME="${FILE_PREFIX}_write.pcap"
LNAME="${FILE_PREFIX}_write_pcap.log"
RNAME="${FILE_PREFIX}_pcap.write.txt"
RNAME_2="${FILE_PREFIX}_pcap.write.2.txt"


function ptcpdump_write() {
  timeout 30s ${CMD} -c 1 -i any --print -w "${FNAME}" \
    'dst host 1.1.1.1 and tcp[tcpflags] = tcp-syn' | tee "${LNAME}" &
  sleep 10
  curl -m 10 1.1.1.1 &>/dev/null || true
  wait

  cat "${LNAME}"
  cat "${LNAME}" | grep -F ' > 1.1.1.1.80: Flags [S],'   # SYN
}

function test_tcpdump_read() {
  which tcpdump || (apt update || true && apt install -y tcpdump)
    timeout 30s tcpdump -n -r "${FNAME}" > "${RNAME}"
    cat "${RNAME}"
    cat "${RNAME}" | grep -F ' > 1.1.1.1.80: Flags [S],'   # SYN
}

function test_ptcpdump_read() {
    timeout 30s ${CMD} -r "${FNAME}" > "${RNAME_2}"
    cat "${RNAME_2}"
    cat "${RNAME_2}" | grep -F ' > 1.1.1.1.80: Flags [S],'   # SYN
}

function main() {
    ptcpdump_write
    test_tcpdump_read
    test_ptcpdump_read
}

main
