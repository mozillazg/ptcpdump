#!/usr/bin/env bash

set -ex

CMD="$1"
TEST_YAML="$2"
FILE_PREFIX="/tmp/ptcpdump"
FNAME="${FILE_PREFIX}_k8s.pcapng"
LNAME="${FILE_PREFIX}_k8s.log"
RNAME="${FILE_PREFIX}_k8s.read.txt"

function test_ptcpdump() {
  timeout 120s ${CMD} -i any -c 10 --print -w "${FNAME}" --oneline -v \
    'host 1.1.1.1' -w "${FNAME}" | tee "${LNAME}" &
  sleep 10

  kubectl delete -f "${TEST_YAML}" || true
  kubectl apply -f "${TEST_YAML}" 
  kubectl wait --for condition=Ready pod/test-ptcpdump
  kubectl wait --for condition=Ready=False --timeout=20s pod/test-ptcpdump
  wait

  cat "${LNAME}"
  cat "${LNAME}" | grep "1.1.1.1.80.*Process (.*wget -T 10 1.1.1.1.*).* Container (.*alpine:3.18.*).* Pod (name test-ptcpdump, namespace default"
}

function test_ptcpdump_read() {
    EXPECT_NAME="${LNAME}.read.expect"
    sed 's/ \(In\|Out\) / /g' "${LNAME}" > "${EXPECT_NAME}"
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
