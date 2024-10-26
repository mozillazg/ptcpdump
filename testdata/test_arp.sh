#!/usr/bin/env bash

set -ex

CMD="$1"
FILE_PREFIX="/tmp/ptcpdump"
FNAME="${FILE_PREFIX}_arp.pcapng"
LNAME="${FILE_PREFIX}_arp.log"
RNAME="${FILE_PREFIX}_arp.read.txt"


function test_ptcpdump() {
  which arping || (apt update || true && apt install -y iputils-arping)
  timeout 30s ${CMD} -c 2 -i any -v --print -w "${FNAME}" \
	  'arp host 1.1.1.1' | tee "${LNAME}" &
  sleep 10
  arping -w 10 -c 2 1.1.1.1 &>/dev/null || true
  wait

  cat "${LNAME}"
  cat "${LNAME}" | grep -F 'ARP, Request who-has 1.1.1.1'
}

function test_tcpdump_read() {
  which tcpdump || (apt update || true && apt install -y tcpdump)
  tcpdump -nr "${FNAME}"
  tcpdump -nr "${FNAME}" | grep -F 'ARP, Request who-has 1.1.1.1'

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
