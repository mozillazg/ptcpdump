#!/usr/bin/env bash

set -ex

CMD="$1"
FILE_PREFIX="/tmp/ptcpdump"
FNAME="${FILE_PREFIX}_parent_info.pcapng"
LNAME="${FILE_PREFIX}_parent_info.log"
RNAME="${FILE_PREFIX}_parent_info.read.txt"


function test_ptcpdump() {
  timeout 30s ${CMD} -c 1 -v -i any --print -w "${FNAME}" \
    'dst host 1.1.1.1 and tcp[tcpflags] = tcp-syn' | tee "${LNAME}" &
  sleep 10
  curl -m 10 1.1.1.1 &>/dev/null || true
  wait

  cat "${LNAME}"
  cat "${LNAME}" | grep '/usr/bin/curl'
  cat "${LNAME}" | grep 'ParentProc'
  cat "${LNAME}" | grep -F ' > 1.1.1.1.80: Flags [S],'   # SYN
}


function test_ptcpdump_read() {
    EXPECT_NAME="${LNAME}.read.expect"
    cat "${LNAME}" > "${EXPECT_NAME}"
    timeout 30s ${CMD} -v -r "${FNAME}" > "${RNAME}"
    cat "${RNAME}" | grep '/usr/bin/curl'
    cat "${RNAME}" | grep 'ParentProc.*test_parent_info.sh'
    cat "${RNAME}" | grep -F ' > 1.1.1.1.80: Flags [S],'   # SYN
}

function main() {
    test_ptcpdump
    test_ptcpdump_read
}

main
