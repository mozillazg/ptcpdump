#!/usr/bin/env bash

set -ex

CMD="$1"
FILE_PREFIX="/tmp/ptcpdump"
FNAME="${FILE_PREFIX}_nat.pcapng"
LNAME="${FILE_PREFIX}_nat.log"
RNAME="${FILE_PREFIX}_nat.read.txt"


function test_ptcpdump() {
  timeout 60s ${CMD} -c 20 -i any -v --print -w "${FNAME}" --oneline  \
    'host 1.1.1.1' | tee "${LNAME}" &
  sleep 10
  docker run --rm alpine:3.18 sh -c 'wget --timeout=10 1.1.1.1 &>/dev/null || true'
  wait

  cat "${LNAME}"
  cat "${LNAME}" | grep 'wget'
  cat "${LNAME}" | grep 'docker0'
  cat "${LNAME}" | grep -F ' > 1.1.1.1.80: Flags [S],'   # SYN
  cat "${LNAME}" | grep 'docker0.* > 1.1.1.1.80: Flags .*, args wget --timeout=10 1.1.1.1'
}

function main() {
    sysctl -w net.ipv4.ip_forward=1

    test_ptcpdump
}

main
