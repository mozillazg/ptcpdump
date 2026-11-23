#!/usr/bin/env bash

# Ingress packets on an L3-only device (here: WireGuard) must carry the
# process of the local socket, just like on Ethernet devices.  With
# --pname, packets without process info are dropped, so the peer's reply
# shows up only if ingress attribution works.

set -ex

NS1="wg_test_ns1"
NS2="wg_test_ns2"
LOCAL_IP="10.9.0.1"
PEER_IP="10.9.0.2"
CMD="$1"
FILE_PREFIX="/tmp/ptcpdump_wireguard"
FNAME="${FILE_PREFIX}.pcapng"
LNAME="${FILE_PREFIX}.log"

cleanup() {
    ip netns del "$NS1" 2>/dev/null || true
    ip netns del "$NS2" 2>/dev/null || true
    rm -f "${FILE_PREFIX}"* || true
}

setup_wireguard() {
    if [ "$(id -u)" -ne 0 ]; then
        echo "This script must be run as root. Please use sudo." >&2
        exit 1
    fi
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

test_ptcpdump() {
    timeout 60s ${CMD} -i wg0 ${PTCPDUMP_EXTRA_ARGS} --netns "$NS1" -v --pname curl --print \
        -w "${FNAME}" "tcp and host $PEER_IP" > "${LNAME}" &
    PTCPDUMP_PID=$!
    sleep 20
    # Nothing listens on the peer, so the reply is a RST.
    ip netns exec "$NS1" curl -m 10 "http://$PEER_IP/" &>/dev/null || true
    sleep 5
    kill "$PTCPDUMP_PID" || true
    wait "$PTCPDUMP_PID" 2>/dev/null || true

    cat "${LNAME}"
    grep -F " > $PEER_IP.80: Flags [S]" "${LNAME}"     # egress
    grep -F "$PEER_IP.80 > $LOCAL_IP." "${LNAME}"      # ingress
}

main() {
    trap cleanup EXIT INT TERM
    if ! modprobe wireguard; then
        echo 'wireguard module not available'
        # skip locally, but don't let CI pass without testing anything
        [ -n "${CI:-}" ] && exit 1
        exit 0
    fi
    setup_wireguard
    test_ptcpdump
}

main
