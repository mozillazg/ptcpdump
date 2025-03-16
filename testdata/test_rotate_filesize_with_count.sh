#!/usr/bin/env bash

set -ex

CMD="$1"
FILE_PREFIX="/tmp/ptcpdump"


function test_ptcpdump() {
  ext="$1"
  FNAME="${FILE_PREFIX}_rotate_cw_$(date +%s).${ext}"

  timeout 60s ${CMD} -C 1kb -W 3 ${PTCPDUMP_EXTRA_ARGS} -i any -w "${FNAME}" \
    'port 80 and host lax-ca-us-ping.vultr.com' &
  curl -m 30 --retry 2 --retry-all-errors http://lax-ca-us-ping.vultr.com/vultr.com.100MB.bin &>/dev/null || true
  wait
  ls -lh ${FNAME}* |head
  test $(ls ${FNAME}* | wc -l) == 3
  for f in $(ls ${FNAME}* | head); do
    ${CMD} -r $f >/dev/null
  done
}


function main() {
    test_ptcpdump pcap
    test_ptcpdump pcapng
}

main
