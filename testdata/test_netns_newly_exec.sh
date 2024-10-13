#!/usr/bin/env bash

set -ex

CMD="$1"
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" > /dev/null && pwd )"
FILE_PREFIX="/tmp/ptcpdump"
CREATE_NS_SCRIPT="${SCRIPT_DIR}/create_netns.sh"
FNAME="${FILE_PREFIX}_netns_newly.pcapng"
LNAME="${FILE_PREFIX}_netns_newly.log"
RNAME="${FILE_PREFIX}_netns_newly.read.txt"
NETNS1="netns30"
VETH1="veth30"
NETNS2="netns31"
VETH2="veth31"

function cleanup() {
    ip netns exec ${NETNS1} ip link delete ${VETH1} || true
    ip netns exec ${NETNS2} ip link delete ${VETH2} || true

    ip netns delete ${NETNS1}
    ip netns delete ${NETNS2}
}

trap cleanup EXIT

function test_ptcpdump_exec() {
  local LNAME="${LNAME}.exec"
  curl 1.1.1.1 &>/dev/null || true &
  ip netns exec ${NETNS2}  sh -c "echo -e 'HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n' | nc -l 8000" &

  timeout 30s ${CMD} -c 4 -i any --netns newly -v --print -w "${FNAME}" \
      'tcp' \
      -- sh -c "bash ${CREATE_NS_SCRIPT} $NETNS1 $VETH1 $NETNS2 $VETH2 && ip netns exec ${NETNS1} curl http://192.168.64.2:8000"  | tee "${LNAME}"

  cat "${LNAME}"
  cat "${LNAME}" | grep '192.168.64.2.* > 192.168.64.1'
  cat "${LNAME}" | grep '192.168.64.1.* > 192.168.64.2'
}

function main() {
  test_ptcpdump_exec
}

main
