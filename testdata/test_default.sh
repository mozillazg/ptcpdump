#!/usr/bin/env bash

set -ex

CMD="$1"
FILE_PREFIX="/tmp/ptcpdump"
FNAME="${FILE_PREFIX}_default.pcapng"
LNAME="${FILE_PREFIX}_default.log"
RNAME="${FILE_PREFIX}_default.read.txt"


function test_ptcpdump() {
  timeout 30s ${CMD} -c 2 -i lo ${PTCPDUMP_EXTRA_ARGS} -v --print -w "${FNAME}" \
      'icmp and host 127.0.0.1' | tee "${LNAME}" &
  sleep 10
  ping -c 1 127.0.0.1 &>/dev/null || true
  wait

  cat "${LNAME}"
  cat "${LNAME}" | grep -F '127.0.0.1 > 127.0.0.1: ICMP echo request'
}

function test_tcpdump_read() {
  which tcpdump || (apt update || true && apt install -y tcpdump)
  tcpdump -nr "${FNAME}"
  tcpdump -nr "${FNAME}" | grep -F '127.0.0.1 > 127.0.0.1: ICMP echo request'

}

function test_ptcpdump_read() {
    EXPECT_NAME="${LNAME}.read.expect"
    cat "${LNAME}" > "${EXPECT_NAME}"
    timeout 30s ${CMD} -v -r "${FNAME}" |tee "${RNAME}"
    cat "${RNAME}" | grep -F '127.0.0.1 > 127.0.0.1: ICMP echo request'
}

function main() {
    test_ptcpdump
    test_tcpdump_read
    test_ptcpdump_read
}

main
