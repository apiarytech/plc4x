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
# Generates PLC4Go's CANopen and Profinet models in this checkout, with Java 21
# and Maven 4 in Docker; nothing Java needs installing. From PowerShell:
#   powershell -ExecutionPolicy Bypass -File plc4go\tools\codegen\generate.ps1
param(
    [string]$Repo = (Join-Path $PSScriptRoot "..\..\..")
)
$ErrorActionPreference = "Stop"

docker info *> $null
if ($LASTEXITCODE -ne 0) { throw "Docker is not running: start Docker Desktop and try again." }

$Repo = (Resolve-Path $Repo).Path
Push-Location $Repo
try {
    Write-Host "Building in Docker; the first run downloads for several minutes."
    docker run --rm `
        -v "${Repo}:/src" `
        -v plc4x-m2:/root/.m2 `
        -w /src maven:3.9-eclipse-temurin-21 sh /src/plc4go/tools/codegen/build-in-container.sh
    $build = $LASTEXITCODE

    foreach ($log in "mvn-install.log", "mvn-generate.log") {
        if (Test-Path $log) {
            $ok = Select-String -Path $log -Pattern "BUILD SUCCESS" -Quiet
            Write-Host ("{0}: {1}" -f $log, $(if ($ok) { "BUILD SUCCESS" } else { "no BUILD SUCCESS, see the end of the log" }))
        }
    }
    foreach ($dir in "plc4go\protocols\canopen", "plc4go\protocols\profinet") {
        if (Test-Path $dir) {
            $n = (Get-ChildItem $dir -Recurse -Filter *.go).Count
            Write-Host "${dir}: $n Go files"
        } else {
            Write-Host "${dir}: not generated"
        }
    }
    if ($build -ne 0) { throw "the build in Docker failed (exit $build); see the logs in $Repo" }
} finally {
    Pop-Location
}
