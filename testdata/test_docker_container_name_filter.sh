#!/usr/bin/env bash

set -ex

CMD="$1"
FILE_PREFIX="/tmp/ptcpdump"
FNAME="${FILE_PREFIX}_filter_by_docker_container_name.pcapng"
LNAME="${FILE_PREFIX}_filter_by_docker_container_name.log"
RNAME="${FILE_PREFIX}_filter_by_docker_container_name.read.txt"


function test_ptcpdump() {
  docker pull busybox:1

  cname='test-ptcpdump'
  cid1=$(docker run --rm -it --name test-ptcpdump -d busybox:1 sh -c 'sleep 20; wget -T 10 1.1.1.1')
  export cid1
  echo $cid1

  timeout 120s ${CMD} -i any -c 10 --print -w "${FNAME}" -v --oneline  \
    --container-name=${cname} -w "${FNAME}" | tee "${LNAME}"

  cat "${LNAME}"
  cat "${LNAME}" | grep "> 1.1.1.1.80: Flags .*, args wget -T 10 1.1.1.1.* $cid1"
}

function test_ptcpdump_read() {
    EXPECT_NAME="${LNAME}.read.expect"
    cat "${LNAME}" > "${EXPECT_NAME}"
    timeout 30s ${CMD} --oneline -v -r "${FNAME}" > "${RNAME}"
    cat "${RNAME}" | grep "> 1.1.1.1.80: Flags .*, args wget -T 10 1.1.1.1.* $cid1"
}


function main() {
    test_ptcpdump
    test_ptcpdump_read
}

main
