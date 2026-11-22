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
	"fmt"

	apiModel "github.com/apache/plc4x/plc4go/pkg/api/model"
	apiValues "github.com/apache/plc4x/plc4go/pkg/api/values"
	readWriteModel "github.com/apache/plc4x/plc4go/protocols/opcua/readwrite/model"
)

type Tag interface {
	apiModel.PlcTag
	GetIdentifierType() readWriteModel.OpcuaIdentifierType
	GetIdentifier() string
	GetNamespace() int
}

func NewTag(namespace int, identifier string, identifierType readWriteModel.OpcuaIdentifierType, dataType readWriteModel.OpcuaDataType) Tag {
	return &tag{
		namespace:      namespace,
		identifier:     identifier,
		identifierType: identifierType,
		dataType:       dataType,
	}
}

type tag struct {
	namespace      int
	identifier     string
	identifierType readWriteModel.OpcuaIdentifierType
	dataType       readWriteModel.OpcuaDataType
	arrayInfo      []apiModel.ArrayInfo // the shape a browse found, nil otherwise
}

// GetAddressString is the address the tag parses from: "ns=2;s=Line1", with ";DINT" when the
// data type is known.
func (t *tag) GetAddressString() string {
	address := fmt.Sprintf("ns=%d;%s=%s", t.namespace, t.identifierType.GetValue(), t.identifier)
	if t.dataType != "" && t.dataType != readWriteModel.OpcuaDataType_NULL {
		address += ";" + t.dataType.PLC4XEnumName()
	}
	return address
}

func (t *tag) GetValueType() apiValues.PlcValueType {
	valueType, ok := apiValues.PlcValueTypeByName(t.dataType.PLC4XEnumName())
	if !ok {
		return 0xFF
	}
	return valueType
}

func (t *tag) GetArrayInfo() []apiModel.ArrayInfo {
	return t.arrayInfo
}

func (t *tag) GetNamespace() int {
	return t.namespace
}

func (t *tag) GetIdentifier() string {
	return t.identifier
}

func (t *tag) GetIdentifierType() readWriteModel.OpcuaIdentifierType {
	return t.identifierType
}

func (t *tag) String() string {
	return fmt.Sprintf("OpcuaTag{namespace=%d,identifierType=%s,identifier=%s}", t.namespace, t.identifierType, t.identifier)
}
