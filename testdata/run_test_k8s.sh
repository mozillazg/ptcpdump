#!/usr/bin/env bash

set -ex

sudo docker cp ./ptcpdump kind-control-plane:/
sudo docker cp ./testdata/test_k8s.yaml kind-control-plane:/
sudo docker cp ./testdata/test_k8s.sh kind-control-plane:/
if [ -n "${GOCOVERDIR}" ]; then
  sudo docker exec kind-control-plane sh -c "mkdir -p ${GOCOVERDIR}"
fi
sudo docker exec kind-control-plane sh -c  "GOCOVERDIR=${GOCOVERDIR} bash /test_k8s.sh /ptcpdump /test_k8s.yaml"
if [ -n "${GOCOVERDIR}" ]; then
  sudo docker exec kind-control-plane sh -c "ls -lh ${GOCOVERDIR}"
  sudo docker cp kind-control-plane:${GOCOVERDIR}/ ${GOCOVERDIR}/
fi
