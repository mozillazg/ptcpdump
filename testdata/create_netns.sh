#!/usr/bin/env bash

set -ex

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" > /dev/null && pwd )"
NETNS1="$1"
VETH1="$2"
NETNS2="$3"
VETH2="$4"

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

function main() {
  setup_netns
}

main
