#!/usr/bin/env bash

set -ex

CMD="$1"
TEST_YAML="$2"
FILE_PREFIX="/tmp/ptcpdump"
FNAME="${FILE_PREFIX}_k8s_filter_by_cid.pcapng"
LNAME="${FILE_PREFIX}_k8s_filter_by_cid.log"
RNAME="${FILE_PREFIX}_k8s_filter_by_cid.read.txt"

function test_ptcpdump() {

  kubectl delete -f "${TEST_YAML}" || true
  kubectl apply -f "${TEST_YAML}" 
  kubectl wait --for condition=Ready pod/test-ptcpdump
  cid=$(kubectl get pod test-ptcpdump -o yaml |grep -i containerID | head -n 1 | awk -F '//' '{print $2}')

  timeout 120s ${CMD} -i any -c 5 --print -w "${FNAME}" --oneline -v \
    --container-id ${cid} -w "${FNAME}" | tee "${LNAME}"

  wait

  cat "${LNAME}"
  cat "${LNAME}" | grep "1.1.1.1.80.*Process (.*wget -T 10 1.1.1.1.*).* Container (.*alpine:3.18.*).* Pod (name test-ptcpdump, namespace default"
}

function test_ptcpdump_read() {
    EXPECT_NAME="${LNAME}.read.expect"
    cat "${LNAME}" > "${EXPECT_NAME}"
    timeout 30s ${CMD} --oneline -v -r "${FNAME}" > "${RNAME}"
    cat "${RNAME}" | grep "1.1.1.1.80.*Process (.*wget -T 10 1.1.1.1.*).* Container (.*alpine:3.18.*).* Pod (name test-ptcpdump, namespace default"
}

function main() {
    rm "${LNAME}" || true
    rm "${RNAME}" || true
    test_ptcpdump
    test_ptcpdump_read
}

main
