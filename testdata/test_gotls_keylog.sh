#!/usr/bin/env bash

set -xe

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" > /dev/null && pwd )"
CMD="$1"
APP_NAME="$(basename $2)"
APP="${SCRIPT_DIR}/gohttpapp/${APP_NAME}"
FILE_PREFIX="/tmp/ptcpdump"
FILE_SUFFIX="${APP_NAME}"
KEYLOG_PATH="${FILE_PREFIX}_keylog_${FILE_SUFFIX}.txt"
PCAP_FILE="${FILE_PREFIX}_keylog_${FILE_SUFFIX}.pcap"
PCAPNG_FILE="${FILE_PREFIX}_keylog_${FILE_SUFFIX}.pcapng"

function test_keylog_to_file() {
    ${CMD} -i any --write-keylog-file ${KEYLOG_PATH} -w ${PCAP_FILE} -- ${APP}
    cat ${KEYLOG_PATH}
    tshark -r ${PCAP_FILE} -o tls.keylog_file:${KEYLOG_PATH} | grep "GET /foo/bar HTTP/1.1"
}

function test_keylog_to_pcapng() {
    ${CMD} -i any --embed-keylog-to-pcapng -w ${PCAPNG_FILE} -- ${APP}
    tshark -r ${PCAPNG_FILE} | grep "GET /foo/bar HTTP/1.1"
}

function main() {
  test_keylog_to_file
  test_keylog_to_pcapng
}

main
