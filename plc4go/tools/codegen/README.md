<!--
  Licensed to the Apache Software Foundation (ASF) under one
  or more contributor license agreements.  See the NOTICE file
  distributed with this work for additional information
  regarding copyright ownership.  The ASF licenses this file
  to you under the Apache License, Version 2.0 (the
  "License"); you may not use this file except in compliance
  with the License.  You may obtain a copy of the License at

    https://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing,
  software distributed under the License is distributed on an
  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
  KIND, either express or implied.  See the License for the
  specific language governing permissions and limitations
  under the License.
-->
# Generating the CANopen and Profinet Go models

Generates `plc4go/protocols/canopen` and `plc4go/protocols/profinet` from the
protocol specs (mspec) in this checkout, with Java 21 and Maven 4 inside
Docker. Nothing Java needs installing on the host.

From the repository root, in PowerShell:

    powershell -ExecutionPolicy Bypass -File plc4go\tools\codegen\generate.ps1

The first run downloads for several minutes (allow up to 30). The Docker
volume `plc4x-m2` keeps the downloads between runs; `docker volume rm
plc4x-m2` removes it. The logs are `mvn-install.log` and `mvn-generate.log` in
the repository root (ignored by git).

What it does (`build-in-container.sh`):

1. Fetches Maven 4 with the image's Maven 3.
2. Installs the Go code generator with CANopen and Profinet, with the
   `update-generated-code` profile (which adds `code-generation/language` to
   the build).
3. Installs the other protocol spec jars without that profile: `plc4go`'s
   pom resolves all of them before any goal runs, and with the profile
   bacnetip, knxnetip and opcua would re-download and rewrite their tracked
   spec files.
4. Runs only the `generate-driver-canopen` and `generate-driver-profinet`
   executions in `plc4go`. The other protocols' generated Go code has hand
   fixes that a regeneration would undo, so they are never regenerated here.

After a run, check that `git status` shows changes only under
`plc4go/protocols/canopen` and `plc4go/protocols/profinet`.

## If it fails

- `docker: ... pull access denied` or network errors: Docker has no internet;
  check its proxy settings.
- Errors resolving a `plc4x-protocols-<name>` `1.1.0-SNAPSHOT` artifact: the
  install step does not build that protocol; add it to the `PROTOCOLS` list in
  `build-in-container.sh`. Other `1.1.0-SNAPSHOT` errors: the Apache snapshot
  repository (repository.apache.org) must be reachable from Docker.
- `requireMavenVersion` failures: the Maven 4 download at the start of
  `build-in-container.sh` did not happen.

## Hand-written files in the generated directories

`protocols/canopen/readwrite/model/StaticHelper.go` and
`protocols/profinet/readwrite/model/StaticHelper.go` hold the functions the
specs call with `STATIC_CALL`, ported from plc4j's `StaticHelper` classes. A
regeneration leaves them in place; keep them when replacing the generated
files.

## Tests

`tests/drivers/tests/canopen_parser_serializer_test.go` and
`profinet_parser_serializer_test.go` run the protocols' parser/serializer
suites (copied to `assets/testing/protocols/`). Profinet skips the testcases
without reference XML and the PTCP DelayReq frames, whose Ethernet padding the
spec does not model.
