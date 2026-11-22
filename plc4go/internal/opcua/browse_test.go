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
	"context"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	apiModel "github.com/apache/plc4x/plc4go/pkg/api/model"
	readWriteModel "github.com/apache/plc4x/plc4go/protocols/opcua/readwrite/model"
	spiModel "github.com/apache/plc4x/plc4go/spi/model"
	"github.com/apache/plc4x/plc4go/spi/testutils"
)

// testNode is a node of the test server's address space.
type testNode struct {
	name       string
	nodeClass  readWriteModel.NodeClass
	children   []string // addresses, in the order the server lists them
	dataType   uint32   // built-in type number of a variable
	valueRank  int32
	dimensions []uint32
	access     uint8
	value      float64
}

// testAddressSpace: Objects holds Line1 and Shared; Line1 holds Speed, Counts and Shared again,
// and refers back to Objects.
func testAddressSpace() map[string]testNode {
	return map[string]testNode{
		OBJECTS_FOLDER:        {name: "Objects", nodeClass: readWriteModel.NodeClass_nodeClassObject, children: []string{"ns=2;s=Line1", "ns=2;i=7"}},
		"ns=2;s=Line1":        {name: "Line1", nodeClass: readWriteModel.NodeClass_nodeClassObject, children: []string{"ns=2;s=Line1.Speed", "ns=2;s=Line1.Counts", "ns=2;i=7", OBJECTS_FOLDER}},
		"ns=2;s=Line1.Speed":  {name: "Speed", nodeClass: readWriteModel.NodeClass_nodeClassVariable, dataType: 11, valueRank: -1, access: 3, value: 12.5},
		"ns=2;s=Line1.Counts": {name: "Counts", nodeClass: readWriteModel.NodeClass_nodeClassVariable, dataType: 6, valueRank: 1, dimensions: []uint32{10}, access: 1},
		"ns=2;i=7":            {name: "Shared", nodeClass: readWriteModel.NodeClass_nodeClassVariable, dataType: 1, valueRank: -1, access: 1},
	}
}

func testNodeId(t *testing.T, address string) readWriteModel.NodeId {
	tag, err := NewTagHandler().ParseTag(address)
	require.NoError(t, err)
	nodeId, err := generateNodeId(tag.(Tag))
	require.NoError(t, err)
	return nodeId
}

func addressOfNodeId(nodeId readWriteModel.NodeId) string {
	return addressOf(readWriteModel.NewExpandedNodeId(false, false, nodeId.GetNodeId(), nil, nil))
}

// browse answers Browse (nodeId set) and BrowseNext (continuation set), one reference per
// answer, so every node with more than one reference needs continuation points.
func (s *testServer) browse(header readWriteModel.RequestHeader, nodeId readWriteModel.NodeId, continuation []byte) (readWriteModel.ExtensionObjectDefinition, error) {
	var address string
	index := 0
	if nodeId != nil {
		address = addressOfNodeId(nodeId)
	} else {
		var err error
		address, index, err = parseContinuation(string(continuation))
		if err != nil {
			return nil, err
		}
	}
	node, ok := s.nodes[address]
	if !ok {
		return readWriteModel.NewBrowseResponse(s.responseHeader(header.GetRequestHandle()),
			[]readWriteModel.BrowseResult{readWriteModel.NewBrowseResult(readWriteModel.NewStatusCode(0x80340000), NULL_BYTE_STRING, nil)}, nil), nil
	}
	var references []readWriteModel.ReferenceDescription
	var next readWriteModel.PascalByteString = NULL_BYTE_STRING
	if index < len(node.children) {
		childAddress := node.children[index]
		child := s.nodes[childAddress]
		childNodeId := testNodeId(s.t, childAddress)
		references = []readWriteModel.ReferenceDescription{readWriteModel.NewReferenceDescription(
			readWriteModel.NewNodeId(readWriteModel.NewNodeIdTwoByte(47)), true,
			readWriteModel.NewExpandedNodeId(false, false, childNodeId.GetNodeId(), nil, nil),
			readWriteModel.NewQualifiedName(2, stringOf(child.name)),
			readWriteModel.NewLocalizedText(true, true, stringOf("en"), stringOf(child.name)),
			child.nodeClass,
			readWriteModel.NewExpandedNodeId(false, false, readWriteModel.NewNodeIdTwoByte(0), nil, nil),
		)}
		if index+1 < len(node.children) {
			next = byteString([]byte(address + "|" + strconv.Itoa(index+1)))
		}
	}
	result := []readWriteModel.BrowseResult{readWriteModel.NewBrowseResult(readWriteModel.NewStatusCode(0), next, references)}
	if nodeId != nil {
		return readWriteModel.NewBrowseResponse(s.responseHeader(header.GetRequestHandle()), result, nil), nil
	}
	return readWriteModel.NewBrowseNextResponse(s.responseHeader(header.GetRequestHandle()), result, nil), nil
}

func parseContinuation(continuation string) (string, int, error) {
	for i := len(continuation) - 1; i >= 0; i-- {
		if continuation[i] == '|' {
			index, err := strconv.Atoi(continuation[i+1:])
			return continuation[:i], index, err
		}
	}
	return "", 0, errAssert("bad continuation point")
}

func (s *testServer) read(request readWriteModel.ReadRequest) (readWriteModel.ExtensionObjectDefinition, error) {
	var results []readWriteModel.DataValue
	for _, nodeToRead := range request.GetNodesToRead() {
		node := s.nodes[addressOfNodeId(nodeToRead.GetNodeId())]
		var value readWriteModel.Variant
		switch nodeToRead.GetAttributeId() {
		case 13:
			value = readWriteModel.NewVariantDouble(false, false, nil, nil, nil, []float64{node.value})
		case ATTRIBUTE_DATA_TYPE:
			value = readWriteModel.NewVariantNodeId(false, false, nil, nil, nil, []readWriteModel.NodeId{
				readWriteModel.NewNodeId(readWriteModel.NewNodeIdTwoByte(uint8(node.dataType)))})
		case ATTRIBUTE_VALUE_RANK:
			value = readWriteModel.NewVariantInt32(false, false, nil, nil, nil, []int32{node.valueRank})
		case ATTRIBUTE_ARRAY_DIMENSIONS:
			if node.dimensions == nil {
				results = append(results, readWriteModel.NewDataValue(false, false, false, false, false, false, nil, nil, nil, nil, nil, nil))
				continue
			}
			length := int32(len(node.dimensions))
			value = readWriteModel.NewVariantUInt32(true, false, nil, nil, &length, node.dimensions)
		case ATTRIBUTE_ACCESS_LEVEL:
			value = readWriteModel.NewVariantByte(false, false, nil, nil, nil, []uint8{node.access})
		}
		results = append(results, readWriteModel.NewDataValue(false, false, false, false, false, true, value, nil, nil, nil, nil, nil))
	}
	return readWriteModel.NewReadResponse(s.responseHeader(request.GetRequestHeader().GetRequestHandle()), results, nil), nil
}

// newBrowseConnection connects a channel to a test server with the address space and wraps it
// in a Connection.
func newBrowseConnection(t *testing.T, configure func(*Configuration)) *Connection {
	configuration := createDefaultConfiguration()
	if configure != nil {
		configure(&configuration)
	}
	rig := newHandshakeRig(t, configuration, identityForTest(t, "server", 2048), nil)
	rig.server.nodes = testAddressSpace()
	require.NoError(t, rig.connect(t))
	connection := rig.connection
	connection.channel = rig.channel
	connection.configuration = rig.channel.configuration
	connection.log = testutils.ProduceTestingLogger(t)
	return connection
}

func browse(t *testing.T, connection *Connection, query string) (apiModel.PlcResponseCode, []apiModel.PlcBrowseItem) {
	parsed, err := NewTagHandler().ParseQuery(query)
	require.NoError(t, err)
	request := spiModel.NewDefaultPlcBrowseRequest(map[string]apiModel.PlcQuery{"q": parsed}, []string{"q"}, connection)
	ctx, cancel := context.WithTimeout(testutils.TestContext(t), 20*time.Second)
	defer cancel()
	select {
	case result := <-connection.Browse(ctx, request):
		require.NoError(t, result.GetErr())
		return result.GetResponse().GetResponseCode("q"), result.GetResponse().GetQueryResults("q")
	case <-ctx.Done():
		t.Fatal("no browse result")
	}
	return 0, nil
}

func TestBrowseTheWholeTree(t *testing.T) {
	connection := newBrowseConnection(t, nil)
	code, items := browse(t, connection, "**")
	require.Equal(t, apiModel.PlcResponseCode_OK, code)

	require.Len(t, items, 2, "Objects holds Line1 and Shared")
	line1, shared := items[0], items[1]
	assert.Equal(t, "Line1", line1.GetName())
	assert.Equal(t, "ns=2;s=Line1", line1.GetTag().GetAddressString())
	assert.False(t, line1.IsReadable(), "an object is not a value")
	assert.Equal(t, "Shared", shared.GetName())
	assert.Equal(t, "ns=2;i=7;BOOL", shared.GetTag().GetAddressString())

	children := line1.GetChildren()
	require.Len(t, children, 4, "Speed, Counts, Shared and Objects")
	speed := children["Speed"]
	assert.Equal(t, "ns=2;s=Line1.Speed;LREAL", speed.GetTag().GetAddressString(), "the data type is in the address")
	assert.True(t, speed.IsReadable())
	assert.True(t, speed.IsWritable())
	assert.True(t, speed.IsSubscribable())
	assert.Empty(t, speed.GetTag().GetArrayInfo())
	assert.Equal(t, "Variable", speed.GetOptions()["node-class"].GetString())

	counts := children["Counts"]
	assert.Equal(t, "ns=2;s=Line1.Counts;DINT", counts.GetTag().GetAddressString())
	assert.True(t, counts.IsReadable())
	assert.False(t, counts.IsWritable(), "read only")
	require.Len(t, counts.GetTag().GetArrayInfo(), 1)
	assert.Equal(t, uint32(10), counts.GetTag().GetArrayInfo()[0].GetSize())

	// Shared and Objects were reached before: listed, not expanded again.
	assert.Empty(t, children["Objects"].GetChildren())
}

func TestBrowseFromANode(t *testing.T) {
	connection := newBrowseConnection(t, nil)
	code, items := browse(t, connection, "ns=2;s=Line1")
	require.Equal(t, apiModel.PlcResponseCode_OK, code)
	names := map[string]bool{}
	for _, item := range items {
		names[item.GetName()] = true
	}
	assert.Equal(t, map[string]bool{"Speed": true, "Counts": true, "Shared": true, "Objects": true}, names)
}

func TestBrowseStopsAtTheLimits(t *testing.T) {
	connection := newBrowseConnection(t, func(c *Configuration) { c.BrowseMaxDepth = 1 })
	_, items := browse(t, connection, "**")
	require.Len(t, items, 2)
	assert.Empty(t, items[0].GetChildren(), "depth 1 lists Objects' children only")

	connection = newBrowseConnection(t, func(c *Configuration) { c.BrowseMaxReferencesPerNode = 1 })
	_, items = browse(t, connection, "**")
	require.Len(t, items, 1, "one reference per node")
}

func TestBrowseOfAMissingNodeFails(t *testing.T) {
	connection := newBrowseConnection(t, nil)
	code, _ := browse(t, connection, "ns=9;s=Nowhere")
	assert.Equal(t, apiModel.PlcResponseCode_INTERNAL_ERROR, code)
}

func TestParseQuery(t *testing.T) {
	for _, query := range []string{"", "**", "ns=2;s=Line1", "ns=0;i=85"} {
		parsed, err := NewTagHandler().ParseQuery(query)
		require.NoError(t, err, query)
		assert.Equal(t, query, parsed.GetQueryString())
	}
	_, err := NewTagHandler().ParseQuery("Line1")
	assert.Error(t, err)
}

// A read goes through the reader to the server and back.
func TestReadThroughTheSession(t *testing.T) {
	connection := newBrowseConnection(t, nil)
	tag, err := NewTagHandler().ParseTag("ns=2;s=Line1.Speed;LREAL")
	require.NoError(t, err)
	request := spiModel.NewDefaultPlcReadRequest(map[string]apiModel.PlcTag{"speed": tag}, []string{"speed"}, NewReader(connection), nil)
	ctx, cancel := context.WithTimeout(testutils.TestContext(t), 10*time.Second)
	defer cancel()
	select {
	case result := <-request.Execute(ctx):
		require.NoError(t, result.GetErr())
		response := result.GetResponse()
		assert.Equal(t, apiModel.PlcResponseCode_OK, response.GetResponseCode("speed"))
		assert.Equal(t, 12.5, response.GetValue("speed").GetFloat64())
	case <-ctx.Done():
		t.Fatal("no read result")
	}
}
