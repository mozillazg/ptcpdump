#!/usr/bin/env bash

set -ex

function main() {
  rm -rf /tmp/ptcpdump_* | true
  kubectl delet pod test-ptcpdump | true

  bash testdata/test_default.sh ./ptcpdump
  bash testdata/test_base.sh ./ptcpdump
  bash testdata/test_parent_info.sh ./ptcpdump

  bash testdata/test_pname_filter.sh ./ptcpdump
  bash testdata/test_pid_filter.sh ./ptcpdump

  bash testdata/test_read_pcap.sh ./ptcpdump
  bash testdata/test_write_pcap.sh ./ptcpdump

  bash testdata/test_exist_connection.sh ./ptcpdump

  bash testdata/test_arp.sh ./ptcpdump
  bash testdata/test_icmp.sh ./ptcpdump

  bash testdata/test_sub_program.sh ./ptcpdump
  bash testdata/test_sub_curl_domain_program.sh ./ptcpdump
  bash testdata/test_write_stdout.sh ./ptcpdump

  bash testdata/test_nat.sh ./ptcpdump

  bash testdata/test_docker.sh ./ptcpdump
  bash testdata/test_docker_container_id_filter.sh ./ptcpdump
  bash testdata/test_docker_container_name_filter.sh ./ptcpdump

  bash testdata/test_containerd.sh ./ptcpdump
  bash testdata/test_containerd_container_id_filter.sh ./ptcpdump
  bash testdata/test_containerd_container_name_filter.sh ./ptcpdump

  bash testdata/run_test_k8s.sh
}

main
