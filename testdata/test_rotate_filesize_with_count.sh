#!/usr/bin/env bash

set -ex

CMD="$1"
FILE_PREFIX="/tmp/ptcpdump"


function test_ptcpdump() {
  ext="$1"
  FNAME="${FILE_PREFIX}_rotate_cw_$(date +%s).${ext}"

  ( \
    printf "HTTP/1.1 200 OK\r\n"; \
    printf "Content-Type: application/octet-stream\r\n"; \
    printf "Content-Length: 104857600\r\n"; \
    printf "Connection: close\r\n"; \
    printf "\r\n"; \
    dd if=/dev/zero bs=1M count=100 status=none; \
  ) | nc -l -p 8087 &

  timeout 20s ${CMD} -C 1kb -W 3 ${PTCPDUMP_EXTRA_ARGS} -i any -w "${FNAME}" \
    'port 8087 and host 127.0.0.1' &
  sleep 10
  curl -m 30 --retry 2 --retry-all-errors http://127.0.0.1:8087 &>/dev/null || true
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
