#!/usr/bin/env bash

set -ex

CMD="$1"
FILE_PREFIX="/tmp/ptcpdump"
FNAME="${FILE_PREFIX}_read.pcap"
LNAME="${FILE_PREFIX}_read_pcap.log"
RNAME="${FILE_PREFIX}_pcap.read.txt"


function tcpdump_write() {
  which tcpdump || (apt update || true && apt install -y tcpdump)
  tcpdump -c 1 -i any -s 0 -n --print -w "${FNAME}" \
    'dst host 1.1.1.1 and tcp[tcpflags] = tcp-syn'
  sleep 30
  curl -m 10 1.1.1.1 &>/dev/null || true
  wait

  cat "${LNAME}"
  cat "${LNAME}" | grep -F ' > 1.1.1.1.80: Flags [S],'   # SYN
}

function test_ptcpdump_read() {
    timeout 30s ${CMD} -r "${FNAME}" > "${RNAME}"
    cat "${RNAME}"
    cat "${RNAME}" | grep -F ' > 1.1.1.1.80: Flags [S],'   # SYN
}

function main() {
    tcpdump_write
    test_ptcpdump_read
}

main
