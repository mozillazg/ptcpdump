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

  timeout 60s ${CMD} -c 200 -i any --print -w "${FNAME}" --oneline --exec-events-worker-number=50 \
    'host 1.1.1.1' | tee "${LNAME}" &
  sleep 10

  cid1=$(docker run --rm -it -d busybox:1 sh -c 'wget -T 10 1.1.1.1')
  echo $cid1

  cid2=$(docker run --rm -it -d alpine:3.18 sh -c 'wget -T 5 1.1.1.1')
  echo $cid2

  sleep 13

  cat "${LNAME}"
  cat "${LNAME}" | grep "> 1.1.1.1.80: Flags .*, args wget -T 10 1.1.1.1.* $cid1"
  cat "${LNAME}" | grep "> 1.1.1.1.80: Flags .*, args wget -T 5 1.1.1.1.* $cid2"
}

function main() {
    test_ptcpdump
}

main
