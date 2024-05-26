#!/usr/bin/env bash

set -ex

CMD="$1"

sysctl -w net.ipv4.ip_forward=1

ip netns add internal


ip link add veth0 type veth peer name veth1
ip link set veth0 netns internal
ip netns exec internal ip addr add 192.168.2.1/24 dev veth0
ip netns exec internal ip link set veth0 up
ip netns exec internal ip route add default via 192.168.2.1


ip netns exec internal sysctl -w net.ipv4.ip_forward=1


iptables -t nat -A POSTROUTING -s 192.168.2.0/24 -o lo -j MASQUERADE

timeout 30s ${CMD} -c 1 -i any --exec-events-worker-number=50 \
    'dst host 1.1.1.1 and tcp[tcpflags] = tcp-syn' &

sleep 10
ip netns exec internal curl -m 10 1.1.1.1

wait
