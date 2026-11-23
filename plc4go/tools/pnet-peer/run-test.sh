#!/bin/sh
# Licensed to the Apache Software Foundation (ASF) under the Apache License, Version 2.0.
#
# Runs the Profinet device test against the p-net sample device, inside the pnet-peer image:
#
#   docker build -t pnet-peer plc4go/tools/pnet-peer
#   docker run --rm --privileged -v "$PWD":/src -w /src/plc4go pnet-peer sh tools/pnet-peer/run-test.sh
#
# The device runs in its own network namespace on one end of a veth pair (192.168.10.2), the
# controller test on the other end (192.168.10.1). p-net's log is printed after the test.
set -e
ip netns add dev
ip link add veth0 type veth peer name veth1
ip link set veth1 netns dev
ip addr add 192.168.10.1/24 dev veth0 && ip link set veth0 up
ip netns exec dev ip link set lo up
ip netns exec dev ip addr add 192.168.10.2/24 dev veth1
ip netns exec dev ip link set veth1 up
mkdir -p /tmp/pnet
(cd /tmp/pnet && ip netns exec dev pn_dev -i veth1 -p /tmp/pnet > /tmp/pnet.log 2>&1 &)
sleep 3
status=0
PROFINET_TEST_INTERFACE=veth0 PROFINET_TEST_DEVICE=rt-labs-dev PROFINET_TEST_GSD=/gsd \
  go test -timeout 120s -count=1 -v -run TestConnectToDevice ./internal/profinet/ || status=$?
echo "---- p-net log"
grep -v '^\s*$' /tmp/pnet.log | tail -40
exit $status
