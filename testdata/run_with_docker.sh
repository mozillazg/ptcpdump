#!/usr/bin/env bash

set -ex

IMAGE="$1"
TMP=${TMP:-/tmp/}
shift

docker run --privileged --rm -t --net=host --pid=host \
  -v /sys/fs/cgroup/:/sys/fs/cgroup/:ro \
  -v /run/netns/:/run/netns/:ro \
  -v ${TMP}:/tmp/ \
  -v `pwd`:/ptcpdump "${IMAGE}" ptcpdump $@
