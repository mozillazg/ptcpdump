#!/usr/bin/env bash

set -ex

NS_NAME="tun_test_ns"
TUN_DEV="tun0"
LOCAL_IP="10.8.0.1"
PEER_IP="10.8.0.2"
CMD="$1"
FILE_PREFIX="/tmp/ptcpdump_tun"
FNAME="${FILE_PREFIX}.pcapng"
LNAME="${FILE_PREFIX}.log"
RNAME="${FILE_PREFIX}.read.txt"

cleanup() {
    echo "--- [CLEANUP] Cleaning up resources... ---"
    if ip netns list | grep -q "$NS_NAME"; then
        echo "[CLEANUP] Deleting network namespace: $NS_NAME"
        sudo ip netns del "$NS_NAME" || true
    fi
    rm -f "${FILE_PREFIX}*" || true
    echo "--- [CLEANUP] Cleanup complete. ---"
}

setup_tun() {
  if [ "$(id -u)" -ne 0 ]; then
      echo "This script must be run as root. Please use sudo." >&2
      exit 1
  fi

  echo "--- [STEP 1] Creating network namespace: $NS_NAME ---"
  sudo ip netns add "$NS_NAME"
  echo "Namespace '$NS_NAME' created."

  echo "--- [STEP 2] Creating and configuring 'tun' device inside '$NS_NAME' ---"
  sudo ip netns exec "$NS_NAME" ip tuntap add dev "$TUN_DEV" mode tun
  sudo ip netns exec "$NS_NAME" ip addr add "$LOCAL_IP" peer "$PEER_IP" dev "$TUN_DEV"
  sudo ip netns exec "$NS_NAME" ip link set dev "$TUN_DEV" up
  echo "Device '$TUN_DEV' created and configured inside '$NS_NAME'."

  echo "--- [STEP 3] Verifying '$TUN_DEV' configuration ---"
  sudo ip netns exec "$NS_NAME" ip addr show "$TUN_DEV"

}

test_tun() {
    echo "--- [STEP 4] Starting packet capture in the background ---"
    sudo timeout 30s ${CMD} -c 4 -i any ${PTCPDUMP_EXTRA_ARGS} --netns $NS_NAME -v --print -w "${FNAME}" \
                                        "icmp and host $PEER_IP" | tee "${LNAME}" &
    PTCPDUMP_PID=$!
    echo "tcpdump started with PID $PTCPDUMP_PID. Capturing packets on '$TUN_DEV'."
    sleep 20

    echo "--- [STEP 5] Generating test traffic with ping ---"
    echo "Pinging peer address $PEER_IP. This is expected to fail as there's no listener."
    sudo ip netns exec "$NS_NAME" ping -c 3 "$PEER_IP" || true

    echo "--- [STEP 6] Stopping packet capture and showing results ---"
    sudo kill "$PTCPDUMP_PID" || true
    wait "$PTCPDUMP_PID" 2>/dev/null || true
    echo "ptcpdump stopped."

    cat "${LNAME}"
    grep -F "$LOCAL_IP > $PEER_IP: ICMP" "${LNAME}"
}

main() {
    trap cleanup EXIT INT TERM
    setup_tun
    test_tun
}

main
