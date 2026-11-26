# Licensed to the Apache Software Foundation (ASF) under one or more contributor license
# agreements. See the NOTICE file distributed with this work for additional information regarding
# copyright ownership. The ASF licenses this file to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance with the License. You may obtain a
# copy of the License at https://www.apache.org/licenses/LICENSE-2.0. Unless required by
# applicable law or agreed to in writing, software distributed under the License is distributed on
# an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#
# Test peers only: two OPC UA servers written independently of plc4x, open62541 (C, v1.4.22, with
# mbedTLS) and asyncua (Python, 2.1.0), next to the Go toolchain, so internal/opcua's
# Connection_server_test.go can run against each in one container. Nothing from either is linked
# into plc4go.
FROM golang:1.27.4
RUN apt-get update -qq && apt-get install -y -qq --no-install-recommends cmake libmbedtls-dev openssl python3 python3-venv && rm -rf /var/lib/apt/lists/*
RUN git clone --depth 1 --branch v1.4.22 --recurse-submodules --shallow-submodules https://github.com/open62541/open62541.git /src/open62541
WORKDIR /src/open62541
RUN cmake -B build -S . -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF -DUA_ENABLE_ENCRYPTION=MBEDTLS \
      -DUA_BUILD_EXAMPLES=OFF -DUA_BUILD_UNIT_TESTS=OFF -DUA_NAMESPACE_ZERO=REDUCED && \
    cmake --build build -j4 && cmake --install build
RUN python3 -m venv /opt/asyncua && /opt/asyncua/bin/pip install -q asyncua==2.1.0
COPY open62541_server.c asyncua_server.py /peer/
RUN cc -O2 -o /usr/local/bin/open62541_server /peer/open62541_server.c -lopen62541 -lmbedtls -lmbedx509 -lmbedcrypto -lpthread
