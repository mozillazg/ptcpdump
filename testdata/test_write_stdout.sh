#!/usr/bin/env bash

set -ex

CMD="$1"
FILE_PREFIX="/tmp/ptcpdump"
RNAME="${FILE_PREFIX}_w_to_stdout.write.txt"


function ptcpdump_write() {
  which tcpdump || (apt update || true && apt install -y tcpdump)
  timeout 30s ${CMD} -c 1 -i any --print -w - \
    'dst host 1.1.1.1 and tcp[tcpflags] = tcp-syn' | tcpdump -c 1 -n -r - > "${RNAME}" &
  sleep 10
  curl -m 10 1.1.1.1 &>/dev/null || true
  wait

  cat "${RNAME}"
  cat "${RNAME}" | grep -F ' > 1.1.1.1.80: Flags [S],'   # SYN
}

function main() {
    ptcpdump_write
}

main
