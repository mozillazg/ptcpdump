#!/usr/bin/env bash

# Ingress packets on an L3-only device (here: WireGuard) must carry the
# process of the local socket, just like on Ethernet devices.
#
# Phase 1 uses --pname: packets without process info are dropped by the BPF
# filter, so the peer's reply shows up only if ingress attribution works.
# Phase 2 runs without a process filter and checks that the ingress packet
# is annotated with the curl process explicitly.

set -ex

NS1="wg_test_ns1"
NS2="wg_test_ns2"
LOCAL_IP="10.9.0.1"
PEER_IP="10.9.0.2"
CMD="$1"
FILE_PREFIX="/tmp/ptcpdump_wireguard"
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

setup_wireguard() {
    # leftovers of an earlier, killed run would make `ip netns add` fail
    cleanup
    which wg || (apt update || true && apt install -y wireguard-tools)
    ip netns add "$NS1"
    ip netns add "$NS2"
    ip link add veth_wg1 netns "$NS1" type veth peer name veth_wg2 netns "$NS2"
    ip -n "$NS1" addr add 192.168.65.1/24 dev veth_wg1
    ip -n "$NS2" addr add 192.168.65.2/24 dev veth_wg2
    ip -n "$NS1" link set veth_wg1 up
    ip -n "$NS2" link set veth_wg2 up

    local key1 key2
    key1=$(wg genkey)
    key2=$(wg genkey)
    ip -n "$NS1" link add wg0 type wireguard
    ip -n "$NS2" link add wg0 type wireguard
    ip netns exec "$NS1" wg set wg0 private-key <(echo "$key1") listen-port 51820 \
        peer "$(echo "$key2" | wg pubkey)" allowed-ips "$PEER_IP/32" endpoint 192.168.65.2:51820
    ip netns exec "$NS2" wg set wg0 private-key <(echo "$key2") listen-port 51820 \
        peer "$(echo "$key1" | wg pubkey)" allowed-ips "$LOCAL_IP/32" endpoint 192.168.65.1:51820
    ip -n "$NS1" addr add "$LOCAL_IP/24" dev wg0
    ip -n "$NS2" addr add "$PEER_IP/24" dev wg0
    ip -n "$NS1" link set wg0 up
    ip -n "$NS2" link set wg0 up
}

start_ptcpdump() {
    rm -f "${FNAME}" "${LNAME}"
    timeout 60s "${CMD}" -i wg0 ${PTCPDUMP_EXTRA_ARGS} --netns "$NS1" -v --print \
        -w "${FNAME}" "$@" "tcp and host $PEER_IP" > "${LNAME}" &
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

test_ingress_with_pname() {
    start_ptcpdump --pname curl
    wait_for_capture
    generate_traffic
    stop_ptcpdump

    cat "${LNAME}"
    grep -F " > $PEER_IP.80: Flags [S]" "${LNAME}"     # egress
    grep -F "$PEER_IP.80 > $LOCAL_IP." "${LNAME}"      # ingress
}

test_ingress_process_info() {
    start_ptcpdump
    wait_for_capture
    generate_traffic
    stop_ptcpdump

    cat "${LNAME}"
    grep -F "$PEER_IP.80 > $LOCAL_IP." "${LNAME}"      # ingress
    grep -A3 -F "$PEER_IP.80 > $LOCAL_IP." "${LNAME}" | grep -E 'Process \(pid [0-9]+, cmd .*/curl'
}

supports_wireguard() {
    modprobe wireguard 2>/dev/null && return 0
    # kernels with CONFIG_WIREGUARD=y have no module to load, try to create a
    # device instead
    ip link add wg_probe_test type wireguard 2>/dev/null || return 1
    ip link del wg_probe_test 2>/dev/null || true
    return 0
}

main() {
    trap cleanup EXIT INT TERM
    if [ "$(id -u)" -ne 0 ]; then
        echo "This script must be run as root. Please use sudo." >&2
        exit 1
    fi
    if ! supports_wireguard; then
        echo 'wireguard is not available'
        # skip locally, but don't let CI pass without testing anything
        [ -n "${CI:-}" ] && exit 1
        exit 0
    fi
    setup_wireguard
    test_ingress_with_pname
    test_ingress_process_info
}

main
