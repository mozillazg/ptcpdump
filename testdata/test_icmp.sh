#!/usr/bin/env bash

set -ex

CMD="$1"
FILE_PREFIX="/tmp/ptcpdump"
FNAME="${FILE_PREFIX}_icmp.pcapng"
LNAME="${FILE_PREFIX}_icmp.log"
RNAME="${FILE_PREFIX}_icmp.read.txt"


function test_ptcpdump() {
  timeout 30s ${CMD} -c 2 -i any --print -v -w "${FNAME}" \
	  'icmp and host 1.1.1.1' | tee "${LNAME}" &
  sleep 10
  ping -w 10 -c 2 1.1.1.1 &>/dev/null || true
  wait

  cat "${LNAME}"
  cat "${LNAME}" | grep -F '> 1.1.1.1: ICMP echo request'
  cat "${LNAME}" | grep -F 'cmd /usr/bin/ping, args ping -w 10 -c 2 1.1.1.1'

}

function test_tcpdump_read() {
  which tcpdump || (apt update || true && apt install -y tcpdump)
  tcpdump -nr "${FNAME}"
  tcpdump -nr "${FNAME}" | grep -F '> 1.1.1.1: ICMP echo request'

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
