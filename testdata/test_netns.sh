#!/usr/bin/env bash

set -ex

CMD="$1"
FILE_PREFIX="/tmp/ptcpdump"
FNAME="${FILE_PREFIX}_netns.pcapng"
LNAME="${FILE_PREFIX}_netns.log"
RNAME="${FILE_PREFIX}_netns.read.txt"
NETNS1="netns10"
VETH1="veth10"
NETNS2="netns11"
VETH2="veth11"


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

function test_ptcpdump_normal() {
  local LNAME="${LNAME}.normal"
  timeout 30s ${CMD} -c 4 -i any --netns ${NETNS1} --netns ${NETNS2} -v --print -w "${FNAME}" \
      'icmp and host 192.168.64.2' | tee "${LNAME}" &
  sleep 10
  ping -c 2 1.1.1.1 &>/dev/null || true &
  ip netns exec ${NETNS1} ping -c 2 192.168.64.2 &>/dev/null || true
  wait

  cat "${LNAME}"
  cat "${LNAME}" | grep -F '192.168.64.1 > 192.168.64.2: ICMP'
  cat "${LNAME}" | grep -F '192.168.64.2 > 192.168.64.1: ICMP'
}

function test_ptcpdump_exec() {
  local LNAME="${LNAME}.exec"
  curl 1.1.1.1 &>/dev/null || true &
  ip netns exec ${NETNS2}  sh -c "echo -e 'HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n' | nc -l 8000" &

  timeout 30s ${CMD} -c 4 -i any --netns any -v --print -w "${FNAME}" \
      'tcp and host 192.168.64.2' \
      -- ip netns exec ${NETNS1} curl http://192.168.64.2:8000  | tee "${LNAME}"

  cat "${LNAME}"
  cat "${LNAME}" | grep '192.168.64.2.* > 192.168.64.1'
  cat "${LNAME}" | grep '192.168.64.1.* > 192.168.64.2'
}

function main() {
  setup_netns
  test_ptcpdump_normal
  test_ptcpdump_exec
}

main
