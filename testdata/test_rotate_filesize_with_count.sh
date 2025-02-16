#!/usr/bin/env bash

set -ex

CMD="$1"
FILE_PREFIX="/tmp/ptcpdump"


function test_ptcpdump() {
  ext="$1"
  FNAME="${FILE_PREFIX}_rotate_cw_$(date +%s).${ext}"

  timeout 30s ${CMD} -C 1kb -W 3 ${PTCPDUMP_EXTRA_ARGS} -i any -w "${FNAME}" \
    'port 80 and host lax-ca-us-ping.vultr.com' &
  curl -m 10 http://lax-ca-us-ping.vultr.com/vultr.com.100MB.bin &>/dev/null || true
  wait
  ls -lh ${FNAME}*
  test $(ls ${FNAME}* | wc -l) == 3
}


function main() {
    test_ptcpdump pcap
    test_ptcpdump pcapng
}

main
