#!/usr/bin/env bash

set -ex

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" > /dev/null && pwd )"

IMAGE="$1"
CMD="bash ${SCRIPT_DIR}/run_with_docker.sh ${IMAGE}"
FILE_PREFIX="/tmp/ptcpdump"
FNAME="${FILE_PREFIX}_run_with_docker_base.pcapng"
LNAME="${FILE_PREFIX}_run_with_docker_base.log"
RNAME="${FILE_PREFIX}_run_with_docker_base.read.txt"
export TMP="/tmp/"


function test_ptcpdump() {
  timeout 60s ${CMD} -c 1 -v -i any --print -w "${FNAME}"  \
    'dst host 1.1.1.1 and tcp[tcpflags] = tcp-syn' | tee "${LNAME}" &
  sleep 30
  curl -m 10 1.1.1.1 &>/dev/null || true
  wait

  cat "${LNAME}"
  cat "${LNAME}" | grep '/usr/bin/curl'
  cat "${LNAME}" | grep -F 'curl -m 10 1.1.1.1'
  cat "${LNAME}" | grep -F ' > 1.1.1.1.80: Flags [S],'   # SYN
}

function test_ptcpdump_read() {
    EXPECT_NAME="${LNAME}.read.expect"
    cat "${LNAME}" |grep -v packets |grep -v WARN > "${EXPECT_NAME}"
    timeout 30s ${CMD} -v -r "${FNAME}" |tee "${RNAME}"
}

function main() {
    test_ptcpdump
    test_ptcpdump_read
}

main
