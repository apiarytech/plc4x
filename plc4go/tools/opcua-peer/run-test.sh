#!/bin/sh
# Licensed to the Apache Software Foundation (ASF) under the Apache License, Version 2.0.
#
# Runs the OPC UA server test against open62541 and asyncua, inside the opcua-peer image:
#
#   docker build -t opcua-peer plc4go/tools/opcua-peer
#   docker run --rm -v "$PWD":/src -w /src/plc4go opcua-peer sh tools/opcua-peer/run-test.sh
#
# Each server gets a fresh certificate whose URI names its application; the test pins it with
# server-certificate-file. Each server's log is printed after its run.
set -e
dir=/tmp/opcua-peer
mkdir -p $dir
certificate() { # name uri
  openssl req -x509 -newkey rsa:2048 -nodes -days 30 -subj "/CN=plc4x test $1" \
    -addext "subjectAltName=URI:$2,DNS:localhost,IP:127.0.0.1" \
    -addext "keyUsage=digitalSignature,nonRepudiation,keyEncipherment,dataEncipherment,keyCertSign" \
    -addext "extendedKeyUsage=serverAuth,clientAuth" \
    -keyout $dir/$1.key.pem -out $dir/$1.cert.pem 2>/dev/null
  openssl x509 -in $dir/$1.cert.pem -outform DER -out $dir/$1.cert.der
  openssl pkey -in $dir/$1.key.pem -outform DER -out $dir/$1.key.der
}
certificate open62541 urn:plc4x:test:open62541
certificate asyncua urn:plc4x:test:asyncua

status=0
run() { # name port: waits for the server to listen, then runs the test
  for i in $(seq 60); do
    grep -qi -e "listening on" -e "server running" $dir/$1.log && break
    sleep 0.5
  done
  OPCUA_TEST_ENDPOINT=127.0.0.1:$2 OPCUA_TEST_SERVER_CERTIFICATE=$dir/$1.cert.der OPCUA_TEST_SERVER=$1 \
    go test -timeout 300s -count=1 -v -run '^TestServer(Reads|ReadOf|Browse|Subscribe|Write|Refuses|Secure)' ./internal/opcua/ || status=1
}
open62541_server 4840 $dir/open62541.cert.der $dir/open62541.key.der > $dir/open62541.log 2>&1 &
pid=$!
run open62541 4840
kill $pid
echo "---- open62541 log"
grep -v '^\s*$' $dir/open62541.log | tail -30
/opt/asyncua/bin/python3 /src/plc4go/tools/opcua-peer/asyncua_server.py 4841 $dir/asyncua.cert.der $dir/asyncua.key.pem > $dir/asyncua.log 2>&1 &
pid=$!
run asyncua 4841
kill $pid
echo "---- asyncua log"
grep -v '^\s*$' $dir/asyncua.log | tail -30
exit $status
