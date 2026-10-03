#!/bin/sh
set -eu
ip netns add security-client
ip link add test-host type veth peer name test-client
ip link set test-client netns security-client
ip addr add 10.203.0.1/24 dev test-host
ip -6 addr add fd42:203::1/64 dev test-host
ip link set test-host up
ip netns exec security-client ip link set lo up
ip netns exec security-client ip addr add 10.203.0.2/24 dev test-client
ip netns exec security-client ip addr add 10.203.0.3/24 dev test-client
ip netns exec security-client ip addr add 10.203.0.4/24 dev test-client
ip netns exec security-client ip -6 addr add fd42:203::2/64 dev test-client
ip netns exec security-client ip link set test-client up
sleep 2
