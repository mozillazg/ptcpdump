#!/usr/bin/env bash

set -ex

IMAGE="$1"
TMP=${TMP:-/tmp/}
shift

docker run --privileged --rm -t --net=host --pid=host \
  -v /sys/kernel/debug/:/sys/kernel/debug/ \
  -v /run/netns/:/run/netns/ \
  -v ${TMP}:/tmp/ \
  -v `pwd`:/ptcpdump "${IMAGE}" ptcpdump $@
