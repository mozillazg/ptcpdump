#!/usr/bin/env bash

set -ex

CMD="$1"
TEST_YAML="$2"
FILE_PREFIX="/tmp/ptcpdump"
FNAME="${FILE_PREFIX}_k8s_filter_by_pod_2.pcapng"
LNAME="${FILE_PREFIX}_k8s_filter_by_pod_2.log"
RNAME="${FILE_PREFIX}_k8s_filter_by_pod_2.read.txt"

function test_ptcpdump() {

  kubectl create ns test-ns || true
  kubectl delete -f "${TEST_YAML}" || true
  kubectl -n test-ns delete -f "${TEST_YAML}" || true
  kubectl -n test-ns apply -f "${TEST_YAML}"
  kubectl -n test-ns wait --for condition=Ready pod/test-ptcpdump

  timeout 120s ${CMD} -i any -c 20 --print -w "${FNAME}" --oneline -v \
    --pod-name "test-ptcpdump.test-ns" | tee "${LNAME}"

  wait

  cat "${LNAME}"
  cat "${LNAME}" | grep "1.1.1.1.80.*Process (.*wget -T 10 1.1.1.1.*).* Container (.*alpine:3.18.*).* Pod (name test-ptcpdump, namespace test-ns"
  cat "${LNAME}" | grep "8.8.8.8.53.*Process (.*wget -T 10 8.8.8.8.*).* Container (.*busybox:1.*).* Pod (name test-ptcpdump, namespace test-ns"
}

function test_ptcpdump_read() {
    EXPECT_NAME="${LNAME}.read.expect"
    cat "${LNAME}" > "${EXPECT_NAME}"
    timeout 30s ${CMD} --oneline -v -r "${FNAME}" > "${RNAME}"
    cat "${RNAME}" | grep "1.1.1.1.80.*Process (.*wget -T 10 1.1.1.1.*).* Container (.*alpine:3.18.*).* Pod (name test-ptcpdump, namespace test-ns"
    cat "${RNAME}" | grep "8.8.8.8.53.*Process (.*wget -T 10 8.8.8.8.*).* Container (.*busybox:1.*).* Pod (name test-ptcpdump, namespace test-ns"
}

function main() {
    rm "${LNAME}" || true
    rm "${RNAME}" || true
    test_ptcpdump
    test_ptcpdump_read
}

main
