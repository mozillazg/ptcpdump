#!/usr/bin/env bash

set -ex

CMD="$1"
TEST_YAML="$2"
FILE_PREFIX="/tmp/ptcpdump"
FNAME="${FILE_PREFIX}_k8s_filter_by_pod.pcapng"
LNAME="${FILE_PREFIX}_k8s_filter_by_pod.log"
RNAME="${FILE_PREFIX}_k8s_filter_by_pod.read.txt"

function test_ptcpdump() {

  kubectl create ns test-ns || true
  kubectl -n test-ns delete -f "${TEST_YAML}" || true
  kubectl -n test-ns apply -f "${TEST_YAML}"
  kubectl -n test-ns wait --for condition=Ready pod/test-ptcpdump
  cid=$(kubectl get pod test-ptcpdump -o yaml |grep -i containerID | head -n 1 | awk -F '//' '{print $2}')

  timeout 120s ${CMD} -i any -c 5 --print -w "${FNAME}" --oneline -v \
    --pod-name "test-ptcpdump.test-ns" -w "${FNAME}" | tee "${LNAME}"

  wait

  cat "${LNAME}"
  cat "${LNAME}" | grep "1.1.1.1.80.*Process (.*wget -T 10 1.1.1.1.*).* Container (.*alpine:3.18.*).* Pod (name test-ptcpdump, namespace test-ns"
}

function test_ptcpdump_read() {
    EXPECT_NAME="${LNAME}.read.expect"
    sed 's/ [a-zA-Z0-9_-]\+ \(In\|Out\) / /g' "${LNAME}" > "${EXPECT_NAME}"
    timeout 30s ${CMD} --oneline -v -r "${FNAME}" > "${RNAME}"
    diff "${EXPECT_NAME}" "${RNAME}"
}

function main() {
    rm "${LNAME}" || true
    rm "${RNAME}" || true
    test_ptcpdump
    test_ptcpdump_read
}

main
