#!/usr/bin/env bash

# The tp_btf hooks are global tracepoints, so the backend has to emulate the
# "capture this device only" scope itself. Two things used to go wrong on a
# veth pair whose ends live in two network namespaces (both ends usually get
# the same ifindex):
#
#  - the filter only matched the ifindex, so a packet could be captured twice,
#    once on the sending device and once on the receiving device, even when
#    only one of them was selected;
#  - the ingress payload starts behind the Ethernet header (eth_type_trans()
#    already pulled it), so the event lost the real MAC addresses and was
#    decoded with a fake Ethernet header.
#
# Phase 1 selects one device: every packet must be captured exactly once.
# Phase 2 selects both ends: both observations must be kept, each annotated
# with its own device and network namespace.

set -ex

NS1="tpbtf_test_ns1"
NS2="tpbtf_test_ns2"
LOCAL_IP="10.31.0.1"
PEER_IP="10.31.0.2"
DEV="tpv"
CMD="$1"
FILE_PREFIX="/tmp/ptcpdump_tpbtf"
FNAME="${FILE_PREFIX}.pcapng"
LNAME="${FILE_PREFIX}.log"
FNAME2="${FILE_PREFIX}.both.pcapng"
LNAME2="${FILE_PREFIX}.both.log"
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

setup_veth() {
    # leftovers of an earlier, killed run would make `ip netns add` fail
    cleanup
    which tcpdump || (apt update || true && apt install -y tcpdump)
    ip netns add "$NS1"
    ip netns add "$NS2"
    ip link add "${DEV}1" netns "$NS1" type veth peer name "${DEV}2" netns "$NS2"
    ip -n "$NS1" addr add "$LOCAL_IP/24" dev "${DEV}1"
    ip -n "$NS2" addr add "$PEER_IP/24" dev "${DEV}2"
    ip -n "$NS1" link set "${DEV}1" up
    ip -n "$NS2" link set "${DEV}2" up
    # both ends normally get the same ifindex; log them for debugging
    ip -n "$NS1" link show "${DEV}1" | head -1
    ip -n "$NS2" link show "${DEV}2" | head -1
}

link_mac() {
    local ns="$1" dev="$2"
    ip -n "$ns" -o link show "$dev" | sed -n 's/.*link\/ether \([0-9a-f:]*\).*/\1/p' | head -1
}

start_ptcpdump() {
    local fname="$1" lname="$2"
    shift 2
    rm -f "${fname}" "${lname}"
    timeout 60s "${CMD}" "$@" ${PTCPDUMP_EXTRA_ARGS} --backend tp-btf -v --print \
        -w "${fname}" "tcp and host $PEER_IP" > "${lname}" &
    PTCPDUMP_PID=$!
}

wait_for_capture() {
    local fname="$1"
    # ptcpdump creates the pcapng file before attaching the hooks
    for _ in $(seq 1 20); do
        [ -s "${fname}" ] && break
        sleep 1
    done
    sleep 3
}

generate_traffic() {
    # one attempt only: the assertions below count the captured packets
    ip netns exec "$NS1" curl -m 2 "http://$PEER_IP/" &>/dev/null || true
    sleep 2
}

stop_ptcpdump() {
    kill "${PTCPDUMP_PID}" 2>/dev/null || true
    wait "${PTCPDUMP_PID}" 2>/dev/null || true
    PTCPDUMP_PID=""
}

# only the sending device is selected: the event from the other end of the
# veth pair must be dropped
test_single_device_scope() {
    local local_mac peer_mac
    local_mac=$(link_mac "$NS1" "${DEV}1")
    peer_mac=$(link_mac "$NS2" "${DEV}2")
    echo "local mac: ${local_mac}, peer mac: ${peer_mac}"

    start_ptcpdump "${FNAME}" "${LNAME}" -i "${DEV}1" --netns "$NS1"
    wait_for_capture "${FNAME}"
    generate_traffic
    stop_ptcpdump

    cat "${LNAME}"

    grep -F " > $PEER_IP.80: Flags [S]" "${LNAME}"     # egress
    grep -F "$PEER_IP.80 > $LOCAL_IP." "${LNAME}"      # ingress
    [ "$(grep -cF " > $PEER_IP.80: Flags [S]" "${LNAME}")" -eq 1 ]
    [ "$(grep -cF "$PEER_IP.80 > $LOCAL_IP." "${LNAME}")" -eq 1 ]

    # the ingress packet carries the process info and the real MAC addresses
    grep -A3 -F "$PEER_IP.80 > $LOCAL_IP." "${LNAME}" | grep -E 'Process \(pid [0-9]+, cmd .*/curl'
    tcpdump -nr "${FNAME}" -e "src host $PEER_IP" | grep -F "$peer_mac > $local_mac"
    [ "$(tcpdump -nr "${FNAME}" 'tcp' 2>/dev/null | wc -l)" -eq 2 ]
}

# both ends are selected: keep both observations and annotate each one with
# its own device and network namespace
test_both_devices_scope() {
    start_ptcpdump "${FNAME2}" "${LNAME2}" -i any --netns "$NS1" --netns "$NS2"
    wait_for_capture "${FNAME2}"
    generate_traffic
    stop_ptcpdump

    cat "${LNAME2}"

    [ "$(grep -cF " > $PEER_IP.80: Flags [S]" "${LNAME2}")" -eq 2 ]
    [ "$(grep -cF "$PEER_IP.80 > $LOCAL_IP." "${LNAME2}")" -eq 2 ]
    [ "$(tcpdump -nr "${FNAME2}" 'tcp' 2>/dev/null | wc -l)" -eq 4 ]

    # sender and receiver side of the SYN
    grep -A1 -E "${DEV}1(@[0-9]+)? Out IP" "${LNAME2}" | grep -qF " > $PEER_IP.80: Flags [S]"
    grep -A1 -E "${DEV}2(@[0-9]+)? In IP" "${LNAME2}" | grep -qF " > $PEER_IP.80: Flags [S]"
    # sender and receiver side of the RST
    grep -A1 -E "${DEV}2(@[0-9]+)? Out IP" "${LNAME2}" | grep -qF "$PEER_IP.80 > $LOCAL_IP."
    grep -A1 -E "${DEV}1(@[0-9]+)? In IP" "${LNAME2}" | grep -qF "$PEER_IP.80 > $LOCAL_IP."
}

main() {
    trap cleanup EXIT INT TERM
    if [ "$(id -u)" -ne 0 ]; then
        echo "This script must be run as root. Please use sudo." >&2
        exit 1
    fi
    setup_veth
    test_single_device_scope
    test_both_devices_scope
}

main
