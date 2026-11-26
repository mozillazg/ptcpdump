#!/usr/bin/env bash

set -ex

CMD="$1"
FILE_PREFIX="/tmp/ptcpdump"
FNAME="${FILE_PREFIX}_btf_layout_header.pcapng"
LNAME="${FILE_PREFIX}_btf_layout_header.log"

BTF_DST="/tmp/vmlinux_btf_layout_header.btf"

function find_btf_src() {
  if [ -n "${BTF_SRC}" ]; then
    return
  fi
  # Kernel 4.x images have no kernel BTF, the e2e workflow copies their BTF
  # file into /var/lib/ptcpdump/btf/vmlinux.
  for f in /sys/kernel/btf/vmlinux /var/lib/ptcpdump/btf/vmlinux; do
    if [ -f "${f}" ]; then
      BTF_SRC=${f}
      return
    fi
  done
}

function build_btf_with_layout_header() {
  # Kernel 7.1+ extends struct btf_header with layout_off/layout_len, but the
  # extra fields are only emitted when the kernel is built with pahole >= 1.31
  # (see `--btf_features=layout` in scripts/Makefile.btf). Make sure this case
  # is always covered by appending the extra header fields to the BTF of the
  # current kernel.
  #
  # All offsets in the header are relative to the end of the header, so they
  # stay valid after inserting the extra fields.
  local hdr_len
  hdr_len=$(od -An -tu4 -j4 -N4 "${BTF_SRC}" | tr -d ' ')

  if [ "${hdr_len}" -lt 32 ]; then
    dd if="${BTF_SRC}" of="${BTF_DST}" bs=1 count=24 status=none
    # layout_off, layout_len, any non-zero value is enough for this test
    printf '\x01\x00\x00\x00\x01\x00\x00\x00' >> "${BTF_DST}"
    dd if="${BTF_SRC}" of="${BTF_DST}" bs=1 skip=24 oflag=append conv=notrunc status=none
    # hdr_len = 32
    printf '\x20\x00\x00\x00' | dd of="${BTF_DST}" bs=1 seek=4 conv=notrunc status=none
  else
    cp "${BTF_SRC}" "${BTF_DST}"
  fi

  od -An -tx1 -N32 "${BTF_DST}"
}

function test_ptcpdump() {
  timeout 30s ${CMD} -c 2 -i lo ${PTCPDUMP_EXTRA_ARGS} --kernel-btf "${BTF_DST}" -v --print -w "${FNAME}" \
      'icmp and host 127.0.0.1' 2>&1 | tee "${LNAME}" &
  sleep 10
  ping -c 1 127.0.0.1 &>/dev/null || true
  wait

  cat "${LNAME}"
  cat "${LNAME}" | grep -F "use BTF specs from ${BTF_DST}"
  cat "${LNAME}" | grep -F '127.0.0.1 > 127.0.0.1: ICMP echo request'
}

function main() {
  find_btf_src
  if [ -z "${BTF_SRC}" ]; then
    echo "no BTF file found" >&2
    exit 1
  fi
  echo "use BTF source: ${BTF_SRC}"

  build_btf_with_layout_header
  test_ptcpdump
}

main
