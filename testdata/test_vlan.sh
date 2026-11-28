#!/usr/bin/env bash

# Ingress packets on a VLAN-tagged L2 device must carry the process of the
# local socket, like untagged traffic.
#
# Two stacked VLAN tags (QinQ) are used on purpose: the kernel pops the outer
# tag before the hooks, so the inner tag stays in the packet data and the
# l2/l3 parsing has to skip it.  Capture on the parent device, not on the
# VLAN subinterface, otherwise the tag is already gone.
#
# With --pname, packets without process info are dropped, so the peer's
# reply shows up only if the ingress attribution works.

set -ex

NS1="vlan_test_ns1"
NS2="vlan_test_ns2"
OUTER_VLAN_ID="100"
INNER_VLAN_ID="200"
LOCAL_IP="10.20.0.1"
PEER_IP="10.20.0.2"
DEV="vv"
CMD="$1"
FILE_PREFIX="/tmp/ptcpdump_vlan"
FNAME="${FILE_PREFIX}.pcapng"
LNAME="${FILE_PREFIX}.log"
PTCPDUMP_PID=""

cleanup() {
    if [ -n "${PTCPDUMP_PID}" ] && kill -0 "${PTCPDUMP_PID}" 2>/dev/null; then
        kill "${PTCPDUMP_PID}" 2>/dev/null || true
        wait "${PTCPDUMP_PID}" 2>/dev/null || true
    fi
    ip netns del "$NS1" 2>/dev/null || true
    ip netns del "$NS2" 2>/dev/null || true
    rm -f "${FILE_PREFIX}"* || true
}

setup_vlan() {
    # leftovers of an earlier, killed run would make `ip netns add` fail
    cleanup
    ip netns add "$NS1"
    ip netns add "$NS2"
    ip link add "${DEV}1" netns "$NS1" type veth peer name "${DEV}2" netns "$NS2"

    ip -n "$NS1" link add link "${DEV}1" name "${DEV}1.${OUTER_VLAN_ID}" type vlan \
        id "$OUTER_VLAN_ID" protocol 802.1ad
    ip -n "$NS2" link add link "${DEV}2" name "${DEV}2.${OUTER_VLAN_ID}" type vlan \
        id "$OUTER_VLAN_ID" protocol 802.1ad
    ip -n "$NS1" link add link "${DEV}1.${OUTER_VLAN_ID}" name "${DEV}1.${OUTER_VLAN_ID}.${INNER_VLAN_ID}" \
        type vlan id "$INNER_VLAN_ID"
    ip -n "$NS2" link add link "${DEV}2.${OUTER_VLAN_ID}" name "${DEV}2.${OUTER_VLAN_ID}.${INNER_VLAN_ID}" \
        type vlan id "$INNER_VLAN_ID"

    ip -n "$NS1" addr add "$LOCAL_IP/24" dev "${DEV}1.${OUTER_VLAN_ID}.${INNER_VLAN_ID}"
    ip -n "$NS2" addr add "$PEER_IP/24" dev "${DEV}2.${OUTER_VLAN_ID}.${INNER_VLAN_ID}"
    for d in "${DEV}1" "${DEV}1.${OUTER_VLAN_ID}" "${DEV}1.${OUTER_VLAN_ID}.${INNER_VLAN_ID}"; do
        ip -n "$NS1" link set "$d" up
    done
    for d in "${DEV}2" "${DEV}2.${OUTER_VLAN_ID}" "${DEV}2.${OUTER_VLAN_ID}.${INNER_VLAN_ID}"; do
        ip -n "$NS2" link set "$d" up
    done
}

start_ptcpdump() {
    rm -f "${FNAME}" "${LNAME}"
    timeout 60s "${CMD}" -i "${DEV}1" ${PTCPDUMP_EXTRA_ARGS} --netns "$NS1" -v --print \
        -w "${FNAME}" "$@" "vlan and tcp and host $PEER_IP" > "${LNAME}" &
    PTCPDUMP_PID=$!
}

wait_for_capture() {
    # ptcpdump creates the pcapng file before attaching the hooks
    for _ in $(seq 1 20); do
        [ -s "${FNAME}" ] && break
        sleep 1
    done
    sleep 2
}

generate_traffic() {
    # Nothing listens on the peer, so every attempt results in a RST.
    # Retry so that a slow ptcpdump startup does not make the test flaky.
    for _ in 1 2 3; do
        ip netns exec "$NS1" curl -m 2 "http://$PEER_IP/" &>/dev/null || true
        sleep 1
        grep -qF "$PEER_IP.80 > $LOCAL_IP." "${LNAME}" && break
    done
    sleep 1
}

stop_ptcpdump() {
    kill "${PTCPDUMP_PID}" 2>/dev/null || true
    wait "${PTCPDUMP_PID}" 2>/dev/null || true
    PTCPDUMP_PID=""
}

test_ptcpdump() {
    start_ptcpdump --pname curl
    wait_for_capture
    generate_traffic
    stop_ptcpdump

    cat "${LNAME}"
    grep -F " > $PEER_IP.80: Flags [S]" "${LNAME}"     # egress
    grep -F "$PEER_IP.80 > $LOCAL_IP." "${LNAME}"      # ingress
    grep -A3 -F "$PEER_IP.80 > $LOCAL_IP." "${LNAME}" | grep -E 'Process \(pid [0-9]+, cmd .*/curl'
    grep -E "${DEV}1(@[0-9]+)? (In|Out) IP" "${LNAME}" # device name with netns
}

main() {
    trap cleanup EXIT INT TERM
    if [ "$(id -u)" -ne 0 ]; then
        echo "This script must be run as root. Please use sudo." >&2
        exit 1
    fi
    if ! command -v curl >/dev/null 2>&1; then
        echo "curl is required" >&2
        exit 1
    fi
    setup_vlan
    test_ptcpdump
}

main
