#!/usr/bin/env bash

set -ex

CMD="$1"
FILE_PREFIX="/tmp/ptcpdump"
FNAME="${FILE_PREFIX}_docker.pcapng"
LNAME="${FILE_PREFIX}_docker.log"
RNAME="${FILE_PREFIX}_docker.read.txt"


function test_ptcpdump() {
  docker pull busybox:1
  docker pull alpine:3.18

  timeout 120s ${CMD} -i any --print -w "${FNAME}" -v --oneline --exec-events-worker-number=50 \
    'host 1.1.1.1' -w "${FNAME}" | tee "${LNAME}" &
  sleep 10

  cid1=$(docker run --rm -it -d busybox:1 sh -c 'sleep 10; wget -T 10 1.1.1.1')
  export cid1
  echo $cid1

  cid2=$(docker run --rm -it -d alpine:3.18 sh -c 'sleep 10; wget -T 5 1.1.1.1')
  export cid2
  echo $cid2

  sleep 25

  cat "${LNAME}"
  cat "${LNAME}" | grep "> 1.1.1.1.80: Flags .*, args wget -T 10 1.1.1.1.* $cid1"
  cat "${LNAME}" | grep "> 1.1.1.1.80: Flags .*, args wget -T 5 1.1.1.1.* $cid2"
}

function test_ptcpdump_read() {
    EXPECT_NAME="${LNAME}.read.expect"
    sed 's/ [a-zA-Z0-9_-]\+ \(In\|Out\) / /g' "${LNAME}" > "${EXPECT_NAME}"
    timeout 30s ${CMD} --oneline -v -r "${FNAME}" > "${RNAME}"
    cat "${RNAME}" | grep "> 1.1.1.1.80: Flags .*, args wget -T 10 1.1.1.1.* $cid1"
    cat "${RNAME}" | grep "> 1.1.1.1.80: Flags .*, args wget -T 5 1.1.1.1.* $cid2"
}


function main() {
    test_ptcpdump
    test_ptcpdump_read
}

main
