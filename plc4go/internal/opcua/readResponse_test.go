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

	"github.com/stretchr/testify/assert"

	apiModel "github.com/apache/plc4x/plc4go/pkg/api/model"
	readWriteModel "github.com/apache/plc4x/plc4go/protocols/opcua/readwrite/model"
	"github.com/apache/plc4x/plc4go/spi/testutils"
)

// A bad status wins over a value beside it: asyncua answers the read of an unknown node with a
// null value and BadNodeIdUnknown.
func TestReadResponseTakesTheStatusOverTheValue(t *testing.T) {
	result := func(status readWriteModel.OpcuaStatusCode, value readWriteModel.Variant) readWriteModel.DataValue {
		return readWriteModel.NewDataValue(false, false, false, false, true, value != nil, value,
			readWriteModel.NewStatusCode(uint32(status)), nil, nil, nil, nil)
	}
	null := readWriteModel.NewVariantNull(false, false, nil, nil)
	_, codes, values := readResponse(testutils.ProduceTestingLogger(t), nil,
		[]string{"unknown", "unknownNoValue", "denied", "good"},
		[]readWriteModel.DataValue{
			result(readWriteModel.OpcuaStatusCode_BadNodeIdUnknown, null),
			result(readWriteModel.OpcuaStatusCode_BadNodeIdUnknown, nil),
			result(readWriteModel.OpcuaStatusCode_BadNotReadable, null),
			result(readWriteModel.OpcuaStatusCode_Good, readWriteModel.NewVariantInt32(false, false, nil, nil, nil, []int32{42})),
		})
	assert.Equal(t, apiModel.PlcResponseCode_NOT_FOUND, codes["unknown"])
	assert.Equal(t, apiModel.PlcResponseCode_NOT_FOUND, codes["unknownNoValue"])
	assert.Equal(t, apiModel.PlcResponseCode_ACCESS_DENIED, codes["denied"])
	assert.Nil(t, values["unknown"])
	assert.Equal(t, apiModel.PlcResponseCode_OK, codes["good"])
	assert.EqualValues(t, 42, values["good"].GetInt32())
}
