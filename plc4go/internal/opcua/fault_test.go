/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package opcua

import (
	"testing"

	"github.com/rs/zerolog"

	apiModel "github.com/apache/plc4x/plc4go/pkg/api/model"
	readWriteModel "github.com/apache/plc4x/plc4go/protocols/opcua/readwrite/model"
)

// serviceFault is a ServiceFault whose service result is status.
func serviceFault(status uint32) readWriteModel.ServiceFault {
	return readWriteModel.NewServiceFault(readWriteModel.NewResponseHeader(0, 1, readWriteModel.NewStatusCode(status),
		readWriteModel.NewDiagnosticInfo(false, false, false, false, false, false, false, nil, nil, nil, nil, nil, nil, nil),
		nil, NULL_EXTENSION_OBJECT))
}

// A request the server answers with a ServiceFault gets the fault's reason
// for every tag, not INTERNAL_ERROR: a write refused for the user's rights
// is ACCESS_DENIED, which is what someone diagnosing it needs to read.
func TestFailedResponseCodesCarryTheServiceFault(t *testing.T) {
	for _, c := range []struct {
		name   string
		body   readWriteModel.ExtensionObjectDefinition
		expect apiModel.PlcResponseCode
	}{
		{"user access denied", serviceFault(uint32(readWriteModel.OpcuaStatusCode_BadUserAccessDenied)), apiModel.PlcResponseCode_ACCESS_DENIED},
		{"not writable", serviceFault(uint32(readWriteModel.OpcuaStatusCode_BadNotWritable)), apiModel.PlcResponseCode_ACCESS_DENIED},
		{"unknown node", serviceFault(uint32(readWriteModel.OpcuaStatusCode_BadNodeIdUnknown)), apiModel.PlcResponseCode_NOT_FOUND},
		{"type mismatch", serviceFault(uint32(readWriteModel.OpcuaStatusCode_BadTypeMismatch)), apiModel.PlcResponseCode_INVALID_DATATYPE},
		{"another bad status", serviceFault(uint32(readWriteModel.OpcuaStatusCode_BadTooManyOperations)), apiModel.PlcResponseCode_REMOTE_ERROR},
		// A fault that says Good is still no answer to the request.
		{"good status in a fault", serviceFault(0), apiModel.PlcResponseCode_INTERNAL_ERROR},
		{"not a fault", readWriteModel.NewReadResponse(serviceFault(0).GetResponseHeader(), nil, nil), apiModel.PlcResponseCode_INTERNAL_ERROR},
		{"no body", nil, apiModel.PlcResponseCode_INTERNAL_ERROR},
	} {
		t.Run(c.name, func(t *testing.T) {
			got := failedResponseCodes(zerolog.Nop(), "Write", []string{"pump", "valve"}, c.body)
			if len(got) != 2 || got["pump"] != c.expect || got["valve"] != c.expect {
				t.Errorf("got %v, want %v for both tags", got, c.expect)
			}
		})
	}
}
