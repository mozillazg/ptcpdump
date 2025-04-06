#!/usr/bin/env bash

set -ex

CMD="$1"
FILE_PREFIX="/tmp/ptcpdump"
FNAME="${FILE_PREFIX}_base.pcapng"
LNAME="${FILE_PREFIX}_base.log"
RNAME="${FILE_PREFIX}_base.read.txt"


function test_ptcpdump() {
  timeout 30s ${CMD} -c 1 -s 0 -nnn -v -i any ${PTCPDUMP_EXTRA_ARGS} --print -w "${FNAME}"  \
    'dst host 1.1.1.1 and tcp[tcpflags] = tcp-syn' | tee "${LNAME}" &
  sleep 10
  curl -m 10 1.1.1.1 &>/dev/null || true
  wait

  cat "${LNAME}"
  cat "${LNAME}" | grep '/usr/bin/curl'
  cat "${LNAME}" | grep -F ' > 1.1.1.1.80: Flags [S],'   # SYN
}

function test_tcpdump_read() {
  which tcpdump || (apt update || true && apt install -y tcpdump)
  tcpdump -nr "${FNAME}"
  tcpdump -nr "${FNAME}" | grep -F ' > 1.1.1.1.80: Flags [S],'   # SYN

  timeout 30s ${CMD} -i any -c 2 -w - | tcpdump -n -r -
}

function test_ptcpdump_read() {
    EXPECT_NAME="${LNAME}.read.expect"
    cat "${LNAME}" > "${EXPECT_NAME}"
    timeout 30s ${CMD} -v -r "${FNAME}" |tee "${RNAME}"
    cat "${RNAME}" | grep '/usr/bin/curl'
    cat "${RNAME}" | grep -F ' > 1.1.1.1.80: Flags [S],'   # SYN

    cat "${FNAME}" | ${CMD} -v -r - |grep '/usr/bin/curl'
    cat "${FNAME}" | ${CMD} -v -r - |grep -F ' > 1.1.1.1.80: Flags [S],'   # SYN
}

function main() {
    test_ptcpdump
    test_tcpdump_read
    test_ptcpdump_read
}

main
