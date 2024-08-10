#!/usr/bin/env bash

set -ex

sudo docker cp ./ptcpdump kind-control-plane:/
sudo docker cp ./testdata/test_k8s_filter_2.yaml kind-control-plane:/
sudo docker cp ./testdata/test_k8s_filter_by_pod_2.sh kind-control-plane:/
sudo docker exec kind-control-plane sh -c  'bash /test_k8s_filter_by_pod_2.sh /ptcpdump /test_k8s_filter_2.yaml'
