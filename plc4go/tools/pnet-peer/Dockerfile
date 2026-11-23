# Licensed to the Apache Software Foundation (ASF) under one or more contributor license
# agreements. See the NOTICE file distributed with this work for additional information regarding
# copyright ownership. The ASF licenses this file to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance with the License. You may obtain a
# copy of the License at https://www.apache.org/licenses/LICENSE-2.0. Unless required by
# applicable law or agreed to in writing, software distributed under the License is distributed on
# an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#
# Test peer only: the open-source p-net Profinet device stack (rtlabs-com/p-net, v0.2.0, the last
# public tag with its CMake build and sample app), built next to the Go toolchain so a test can run
# the sample device in one network namespace and the plc4go controller in another. Nothing from
# p-net is linked into plc4go.
FROM golang:1.27.4
ARG LOG_LEVEL=INFO
RUN apt-get update -qq && apt-get install -y -qq --no-install-recommends cmake iproute2 tcpdump && rm -rf /var/lib/apt/lists/*
RUN git clone --depth 1 --branch v0.2.0 --recurse-submodules --shallow-submodules https://github.com/rtlabs-com/p-net.git /src/p-net
WORKDIR /src/p-net
# A veth link has no copper or fiber port type, so p-net would call its medium unknown and refuse
# the parameterization end for lack of a fast enough port. Treat an unknown medium as 100BASE-TX.
RUN sed -i 's/^   return PNAL_ETH_MAU_UNKNOWN;$/   return PNAL_ETH_MAU_COPPER_100BaseTX_FULL_DUPLEX;/' src/ports/linux/pnal.c &&     grep -n "return PNAL_ETH_MAU_COPPER_100BaseTX_FULL_DUPLEX;$" src/ports/linux/pnal.c
RUN cmake -B build -S . -DBUILD_TESTING=OFF -DCMAKE_BUILD_TYPE=Release -DLOG_LEVEL=${LOG_LEVEL} && cmake --build build -j4
# The sample app calls these helper scripts for LEDs and IP settings; in a container they do nothing.
RUN set -e; f=$(find build -maxdepth 2 -type f -name 'pn_dev' | head -1); cp "$f" /usr/local/bin/pn_dev; \
    mkdir -p /gsd && cp sample_app/GSDML*.xml /gsd/; \
    for s in set_profinet_leds set_network_parameters; do printf '#!/bin/sh\nexit 0\n' > /usr/local/bin/$s; chmod +x /usr/local/bin/$s; done; \
    ls -la /usr/local/bin/pn_dev /gsd
