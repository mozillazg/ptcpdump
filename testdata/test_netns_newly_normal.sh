#!/usr/bin/env bash

set -ex

CMD="$1"
FILE_PREFIX="/tmp/ptcpdump"
FNAME="${FILE_PREFIX}_netns_newly.pcapng"
LNAME="${FILE_PREFIX}_netns_newly.log"
RNAME="${FILE_PREFIX}_netns_newly.read.txt"
NETNS1="netns20"
VETH1="veth20"
NETNS2="netns21"
VETH2="veth21"

function setup_netns() {
    ip netns add ${NETNS1} || true
    ip netns add ${NETNS2} || true

    ip link add ${VETH1} type veth peer name ${VETH2} || true
    ip link set ${VETH1} netns ${NETNS1} || true
    ip link set ${VETH2} netns ${NETNS2} || true

    ip -n ${NETNS1} addr add 192.168.64.1/24 dev ${VETH1} || true
    ip -n ${NETNS2} addr add 192.168.64.2/24 dev ${VETH2} || true

    ip -n ${NETNS1} link set ${VETH1} up
    ip -n ${NETNS2} link set ${VETH2} up
}

function cleanup() {
    ip netns exec ${NETNS1} ip link delete ${VETH1} || true
    ip netns exec ${NETNS2} ip link delete ${VETH2} || true

    ip netns delete ${NETNS1}
    ip netns delete ${NETNS2}
}

trap cleanup EXIT

function test_ptcpdump_normal() {
  local LNAME="${LNAME}.normal"
  timeout 30s ${CMD} -c 4 -i any --netns newly -v --print -w "${FNAME}" \
      'icmp' | tee "${LNAME}" &
  sleep 10
  setup_netns

  ping -c 5 1.1.1.1 &>/dev/null || true &
  ip netns exec ${NETNS1} ping -c 2 192.168.64.2 &>/dev/null || true
  wait

  cat "${LNAME}"
  cat "${LNAME}" | grep -F '192.168.64.1 > 192.168.64.2: ICMP'
  cat "${LNAME}" | grep -F '192.168.64.2 > 192.168.64.1: ICMP'
}

function main() {
  test_ptcpdump_normal
}

main
