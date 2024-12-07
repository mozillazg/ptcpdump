#!/usr/bin/env bash

set -ex

CMD="$1"
FILE_PREFIX="/tmp/ptcpdump"
FNAME="${FILE_PREFIX}_ifindex_cgroup_skb.pcapng"
LNAME="${FILE_PREFIX}_ifindex_cgroup_skb.log"
RNAME="${FILE_PREFIX}_ifindex_cgroup_skb.read.txt"


function test_ptcpdump() {
  timeout 30s ${CMD} -c 2 --backend=cgroup-skb -v -i lo --print -w "${FNAME}"  \
    'icmp' | tee "${LNAME}" &
  sleep 10
  ping -c 10 1.1.1.1 &>/dev/null || true &
  ping -c 2 127.0.0.1 &>/dev/null || true
  wait

  cat "${LNAME}"
  cat "${LNAME}" | grep 'ping'
  cat "${LNAME}" | grep -F ' > 127.0.0.1: ICMP echo request,'
}

function test_tcpdump_read() {
  which tcpdump || (apt update || true && apt install -y tcpdump)
  tcpdump -nr "${FNAME}"
  tcpdump -nr "${FNAME}" | grep -F ' > 127.0.0.1: ICMP echo request,'
}

function test_ptcpdump_read() {
    EXPECT_NAME="${LNAME}.read.expect"
    cat "${LNAME}" > "${EXPECT_NAME}"
    timeout 30s ${CMD} -v -r "${FNAME}" |tee "${RNAME}"
    cat "${RNAME}" | grep 'ping'
    cat "${RNAME}" | grep -F ' > 127.0.0.1: ICMP echo request,'
}

function main() {
    test_ptcpdump
    test_tcpdump_read
    test_ptcpdump_read
}

main
