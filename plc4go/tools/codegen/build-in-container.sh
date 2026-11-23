#!/bin/sh
#
# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.
#
# Runs inside the maven:3.9-eclipse-temurin-21 container, with this plc4x
# checkout mounted at /src. PLC4X needs Maven 4, which the image lacks: fetch
# it with the image's Maven 3, then build the code generator and every
# protocol spec jar the plc4go module depends on (Maven resolves all of them,
# with their test jars, before any goal runs), and generate only the CANopen
# and Profinet Go models (the other protocols' generated code has hand fixes a
# regeneration would undo; installing their spec jars generates nothing).
set -e
MAVEN=4.0.0-rc-5
cd /tmp
mvn -B -q dependency:get -Dartifact=org.apache.maven:apache-maven:$MAVEN:tar.gz:bin
tar xzf /root/.m2/repository/org/apache/maven/apache-maven/$MAVEN/apache-maven-$MAVEN-bin.tar.gz -C /opt
M=/opt/apache-maven-$MAVEN/bin/mvn
cd /src
echo "== installing the generator and the protocol specs (log: mvn-install.log)"
# Pass 1, with update-generated-code (it adds code-generation/language to the
# build): the Go generator and the two protocols being generated.
$M -B -DskipTests -Drat.skip=true -P with-go,update-generated-code -pl code-generation/language/go,protocols/canopen,protocols/profinet -am install > mvn-install.log 2>&1
# Pass 2, without that profile: the other protocol specs plc4go's pom needs.
# With the profile, bacnetip, knxnetip and opcua would re-download and rewrite
# their tracked spec files.
PROTOCOLS=""
for p in ab-eth ads bacnetip c-bus df1 eip firmata iec-60870 knxnetip modbus opcua s7 simulated slmp umas; do
  PROTOCOLS="$PROTOCOLS${PROTOCOLS:+,}protocols/$p"
done
$M -B -DskipTests -Drat.skip=true -P with-go -pl $PROTOCOLS -am install >> mvn-install.log 2>&1
echo "== generating CANopen and Profinet (log: mvn-generate.log)"
$M -B -P with-go,update-generated-code -pl plc4go \
  org.apache.plc4x.plugins:plc4x-maven-plugin:generate-driver@generate-driver-canopen \
  org.apache.plc4x.plugins:plc4x-maven-plugin:generate-driver@generate-driver-profinet > mvn-generate.log 2>&1
echo "== done"
