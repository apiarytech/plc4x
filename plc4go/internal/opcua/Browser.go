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
	"fmt"
	"runtime/debug"
	"strings"
	"uuid"

	apiModel "github.com/apache/plc4x/plc4go/pkg/api/model"
	apiValues "github.com/apache/plc4x/plc4go/pkg/api/values"
	readWriteModel "github.com/apache/plc4x/plc4go/protocols/opcua/readwrite/model"
	"github.com/apache/plc4x/plc4go/spi/errors"
	spiModel "github.com/apache/plc4x/plc4go/spi/model"
	"github.com/apache/plc4x/plc4go/spi/utils"
	spiValues "github.com/apache/plc4x/plc4go/spi/values"
)

const (
	// OBJECTS_FOLDER is the standard Objects folder, where a browse of everything starts.
	OBJECTS_FOLDER = "ns=0;i=85"
	// HIERARCHICAL_REFERENCES (with its subtypes) gives the containment tree: Organizes,
	// HasComponent, HasProperty and the like, not type definitions.
	HIERARCHICAL_REFERENCES = uint32(33)
	// BROWSE_RESULT_MASK_ALL asks for every field of a reference.
	BROWSE_RESULT_MASK_ALL = uint32(0x3F)
)

// The attributes read for each variable a browse finds (OPC UA Part 6, A.1).
const (
	ATTRIBUTE_DATA_TYPE        = uint32(14)
	ATTRIBUTE_VALUE_RANK       = uint32(15)
	ATTRIBUTE_ARRAY_DIMENSIONS = uint32(16)
	ATTRIBUTE_ACCESS_LEVEL     = uint32(17)
)

// ANY_LENGTH is the upper bound of an array dimension whose length the server leaves open, as
// PLC4J's -1.
const ANY_LENGTH = ^uint32(0)

var browseAttributes = []uint32{ATTRIBUTE_DATA_TYPE, ATTRIBUTE_VALUE_RANK, ATTRIBUTE_ARRAY_DIMENSIONS, ATTRIBUTE_ACCESS_LEVEL}

// Query is an OPC UA browse query: the address of the node to start from ("ns=2;s=Line1"),
// or empty or "**" for the Objects folder.
type Query struct {
	query string
}

var _ apiModel.PlcQuery = Query{}

func (q Query) GetQueryString() string {
	return q.query
}

func (q Query) String() string {
	return "opcua.Query{" + q.query + "}"
}

// startAddress is the address of the node the query starts from.
func (q Query) startAddress() string {
	if query := strings.TrimSpace(q.query); query != "" && query != "**" {
		return query
	}
	return OBJECTS_FOLDER
}

func (c *Connection) Browse(ctx context.Context, browseRequest apiModel.PlcBrowseRequest) <-chan apiModel.PlcBrowseRequestResult {
	return c.BrowseWithInterceptor(ctx, browseRequest, func(apiModel.PlcBrowseItem) bool { return true })
}

// BrowseWithInterceptor lists, for each query, the tree of nodes under its start node along the
// hierarchical references, as PLC4J does: every node once, variables with their data type,
// array shape and access rights.
func (c *Connection) BrowseWithInterceptor(ctx context.Context, browseRequest apiModel.PlcBrowseRequest, interceptor func(result apiModel.PlcBrowseItem) bool) <-chan apiModel.PlcBrowseRequestResult {
	result := make(chan apiModel.PlcBrowseRequestResult, 1)
	c.wg.Go(func() {
		defer func() {
			if err := recover(); err != nil {
				utils.DeliverResult(c.log, result, spiModel.NewDefaultPlcBrowseRequestResult(browseRequest, nil,
					errors.Errorf("panic-ed %v. Stack: %s", err, debug.Stack())))
			}
		}()
		responseCodes := map[string]apiModel.PlcResponseCode{}
		results := map[string][]apiModel.PlcBrowseItem{}
		for _, queryName := range browseRequest.GetQueryNames() {
			code, items := c.browseQuery(ctx, interceptor, queryName, browseRequest.GetQuery(queryName))
			responseCodes[queryName] = code
			results[queryName] = items
		}
		utils.DeliverResult(c.log, result, spiModel.NewDefaultPlcBrowseRequestResult(browseRequest,
			spiModel.NewDefaultPlcBrowseResponse(browseRequest, results, responseCodes), nil))
	})
	return result
}

func (c *Connection) browseQuery(ctx context.Context, interceptor func(result apiModel.PlcBrowseItem) bool, queryName string, query apiModel.PlcQuery) (apiModel.PlcResponseCode, []apiModel.PlcBrowseItem) {
	opcuaQuery, ok := query.(Query)
	if !ok {
		c.log.Warn().Type("query", query).Msg("Not an OPC UA browse query")
		return apiModel.PlcResponseCode_INVALID_ADDRESS, nil
	}
	start, err := NewTagHandler().ParseTag(opcuaQuery.startAddress())
	if err != nil {
		c.log.Warn().Err(err).Str("query", queryName).Msg("Invalid browse start node")
		return apiModel.PlcResponseCode_INVALID_ADDRESS, nil
	}
	nodeId, err := generateNodeId(start.(Tag))
	if err != nil {
		c.log.Warn().Err(err).Str("query", queryName).Msg("Invalid browse start node")
		return apiModel.PlcResponseCode_INVALID_ADDRESS, nil
	}
	b := &browser{
		connection:  c,
		queryName:   queryName,
		interceptor: interceptor,
		visited:     map[string]bool{tagAddress(start.(Tag)): true},
	}
	items, err := b.browseNode(ctx, nodeId, 0)
	if err != nil {
		c.log.Warn().Err(err).Str("query", queryName).Msg("Browsing failed")
		return apiModel.PlcResponseCode_INTERNAL_ERROR, nil
	}
	return apiModel.PlcResponseCode_OK, items
}

// browser walks the tree of one query. visited holds every node seen, so a node is expanded
// once however many references lead to it, and a reference cycle ends by itself.
type browser struct {
	connection  *Connection
	queryName   string
	interceptor func(result apiModel.PlcBrowseItem) bool
	visited     map[string]bool
}

func (b *browser) browseNode(ctx context.Context, nodeId readWriteModel.NodeId, depth int) ([]apiModel.PlcBrowseItem, error) {
	configuration := b.connection.configuration
	if configuration.BrowseMaxDepth > 0 && depth >= configuration.BrowseMaxDepth {
		b.connection.log.Warn().Str("query", b.queryName).Int("depth", depth).
			Msg("Stopped browsing at browse-max-depth; raise it if the tree is legitimately deeper")
		return nil, nil
	}
	references, err := b.references(ctx, nodeId)
	if err != nil {
		return nil, err
	}
	attributes, err := b.variableAttributes(ctx, references)
	if err != nil {
		// The tree is still worth having: items fall back to what the references say.
		b.connection.log.Warn().Err(err).Msg("Reading the attributes of browsed variables failed")
	}
	var items []apiModel.PlcBrowseItem
	for _, reference := range references {
		address := addressOf(reference.GetNodeId())
		if address == "" {
			continue // an identifier the driver cannot address, such as an opaque one
		}
		children := map[string]apiModel.PlcBrowseItem{}
		switch {
		case b.visited[address]:
			// Listed again, not expanded again.
		case configuration.BrowseMaxTotalNodes > 0 && len(b.visited) >= configuration.BrowseMaxTotalNodes:
			b.connection.log.Warn().Str("query", b.queryName).Int("nodes", len(b.visited)).
				Msg("Stopped expanding nodes at browse-max-total-nodes")
		default:
			b.visited[address] = true
			childTag, err := NewTagHandler().ParseTag(address)
			if err != nil {
				return nil, err
			}
			childNodeId, err := generateNodeId(childTag.(Tag))
			if err != nil {
				return nil, err
			}
			childItems, err := b.browseNode(ctx, childNodeId, depth+1)
			if err != nil {
				return nil, err
			}
			for _, child := range childItems {
				if _, taken := children[child.GetName()]; !taken {
					children[child.GetName()] = child
				}
			}
		}
		item := buildBrowseItem(reference, address, attributes[address], children)
		if b.interceptor != nil && !b.interceptor(item) {
			continue
		}
		items = append(items, item)
	}
	return items, nil
}

// references returns the forward hierarchical references of a node, following continuation
// points until the server has sent them all or browse-max-references-per-node is reached.
func (b *browser) references(ctx context.Context, nodeId readWriteModel.NodeId) ([]readWriteModel.ReferenceDescription, error) {
	channel := b.connection.channel
	codec := b.connection.messageCodec
	maxReferences := b.connection.configuration.BrowseMaxReferencesPerNode
	response, err := channel.call(ctx, codec, readWriteModel.NewBrowseRequest(
		channel.newRequestHeader(channel.getRequestHandle()),
		readWriteModel.NewViewDescription(readWriteModel.NewNodeId(readWriteModel.NewNodeIdTwoByte(0)), 0, 0),
		uint32(max(0, maxReferences)),
		[]readWriteModel.BrowseDescription{readWriteModel.NewBrowseDescription(
			nodeId,
			readWriteModel.BrowseDirection_browseDirectionForward,
			readWriteModel.NewNodeId(readWriteModel.NewNodeIdTwoByte(uint8(HIERARCHICAL_REFERENCES))),
			true,
			0, // every node class
			BROWSE_RESULT_MASK_ALL,
		)},
	))
	var references []readWriteModel.ReferenceDescription
	for {
		if err != nil {
			return nil, errors.Wrap(err, "Browse failed")
		}
		var results []readWriteModel.BrowseResult
		switch response := response.(type) {
		case readWriteModel.BrowseResponse:
			results = response.GetResults()
		case readWriteModel.BrowseNextResponse:
			results = response.GetResults()
		default:
			return nil, errors.Errorf("unexpected response %T to Browse", response)
		}
		if len(results) != 1 {
			return nil, errors.Errorf("Browse returned %d results for one node", len(results))
		}
		result := results[0]
		if statusCode := result.GetStatusCode().GetStatusCode(); statusCode&0x80000000 != 0 {
			return nil, errors.Errorf("Browse failed with status %s", statusName(statusCode))
		}
		references = append(references, result.GetReferences()...)
		continuationPoint := result.GetContinuationPoint()
		if continuationPoint == nil || len(continuationPoint.GetStringValue()) == 0 {
			return references, nil
		}
		release := maxReferences > 0 && len(references) >= maxReferences
		response, err = channel.call(ctx, codec, readWriteModel.NewBrowseNextRequest(
			channel.newRequestHeader(channel.getRequestHandle()),
			release,
			[]readWriteModel.PascalByteString{continuationPoint},
		))
		if release {
			b.connection.log.Warn().Int("references", len(references)).
				Msg("Stopped collecting the references of a node at browse-max-references-per-node")
			return references, nil
		}
	}
}

// nodeAttributes are what a browse reads of a variable.
type nodeAttributes struct {
	dataType  readWriteModel.OpcuaDataType // NULL when not a built-in type
	arrayInfo []apiModel.ArrayInfo
	readable  bool
	writable  bool
}

// variableAttributes reads the data type, value rank, array dimensions and access level of the
// variables among references, in one Read, keyed by address.
func (b *browser) variableAttributes(ctx context.Context, references []readWriteModel.ReferenceDescription) (map[string]nodeAttributes, error) {
	var addresses []string
	var nodesToRead []readWriteModel.ReadValueId
	seen := map[string]bool{}
	for _, reference := range references {
		if reference.GetNodeClass() != readWriteModel.NodeClass_nodeClassVariable {
			continue
		}
		address := addressOf(reference.GetNodeId())
		if address == "" || seen[address] {
			continue
		}
		seen[address] = true
		addresses = append(addresses, address)
		nodeId := readWriteModel.NewNodeId(reference.GetNodeId().GetNodeId())
		for _, attribute := range browseAttributes {
			nodesToRead = append(nodesToRead, readWriteModel.NewReadValueId(nodeId, attribute, NULL_STRING, readWriteModel.NewQualifiedName(0, NULL_STRING)))
		}
	}
	if len(addresses) == 0 {
		return nil, nil
	}
	channel := b.connection.channel
	response, err := channel.call(ctx, b.connection.messageCodec, readWriteModel.NewReadRequest(
		channel.newRequestHeader(channel.getRequestHandle()),
		0,
		readWriteModel.TimestampsToReturn_timestampsToReturnNeither,
		nodesToRead,
	))
	if err != nil {
		return nil, err
	}
	readResponse, ok := response.(readWriteModel.ReadResponse)
	if !ok {
		return nil, errors.Errorf("unexpected response %T to Read", response)
	}
	values := readResponse.GetResults()
	if len(values) != len(nodesToRead) {
		return nil, errors.Errorf("Read returned %d values for %d attributes", len(values), len(nodesToRead))
	}
	attributes := map[string]nodeAttributes{}
	for i, address := range addresses {
		attributes[address] = attributesFrom(values[i*len(browseAttributes):])
	}
	return attributes, nil
}

// attributesFrom reads the four attribute values of one variable.
func attributesFrom(values []readWriteModel.DataValue) nodeAttributes {
	attributes := nodeAttributes{dataType: readWriteModel.OpcuaDataType_NULL, readable: true, writable: true}
	if dataType, ok := variantValue(values[0]).(readWriteModel.VariantNodeId); ok && len(dataType.GetValue()) > 0 {
		attributes.dataType = builtInDataType(dataType.GetValue()[0])
	}
	if accessLevel, ok := variantValue(values[3]).(readWriteModel.VariantByte); ok && len(accessLevel.GetValue()) > 0 {
		attributes.readable = accessLevel.GetValue()[0]&0x01 != 0
		attributes.writable = accessLevel.GetValue()[0]&0x02 != 0
	}
	valueRank, ok := variantValue(values[1]).(readWriteModel.VariantInt32)
	if !ok || len(valueRank.GetValue()) == 0 || valueRank.GetValue()[0] < 0 {
		return attributes // a scalar (or a rank that says nothing about an array)
	}
	if dimensions, ok := variantValue(values[2]).(readWriteModel.VariantUInt32); ok && len(dimensions.GetValue()) > 0 {
		for _, dimension := range dimensions.GetValue() {
			upper := dimension - 1
			if dimension == 0 {
				upper = ANY_LENGTH
			}
			attributes.arrayInfo = append(attributes.arrayInfo, &spiModel.DefaultArrayInfo{UpperBound: upper})
		}
		return attributes
	}
	for range max(valueRank.GetValue()[0], 1) {
		attributes.arrayInfo = append(attributes.arrayInfo, &spiModel.DefaultArrayInfo{UpperBound: ANY_LENGTH})
	}
	return attributes
}

func variantValue(value readWriteModel.DataValue) readWriteModel.Variant {
	if value == nil || !value.GetValueSpecified() {
		return nil
	}
	return value.GetValue()
}

// builtInDataType maps a DataType node to the built-in type it names: the built-in DataType
// nodes of namespace 0 share their numbers with the Variant types. Others (abstract, enum,
// structure and custom types) map to NULL.
func builtInDataType(nodeId readWriteModel.NodeId) readWriteModel.OpcuaDataType {
	var namespace, id uint32
	switch definition := nodeId.GetNodeId().(type) {
	case readWriteModel.NodeIdTwoByte:
		id = uint32(definition.GetId())
	case readWriteModel.NodeIdFourByte:
		namespace, id = uint32(definition.GetNamespaceIndex()), uint32(definition.GetId())
	case readWriteModel.NodeIdNumeric:
		namespace, id = uint32(definition.GetNamespaceIndex()), definition.GetId()
	default:
		return readWriteModel.OpcuaDataType_NULL
	}
	if namespace != 0 || id == 0 || id > 25 {
		return readWriteModel.OpcuaDataType_NULL
	}
	if dataType, ok := readWriteModel.OpcuaDataTypeFirstEnumForFieldVariantType(uint8(id)); ok {
		return dataType
	}
	return readWriteModel.OpcuaDataType_NULL
}

// addressOf is the tag address of a node ("ns=2;s=Line1"), or "" for a node on another server
// or with an identifier the tag syntax cannot carry.
func addressOf(nodeId readWriteModel.ExpandedNodeId) string {
	if nodeId == nil || nodeId.GetServerIndexSpecified() || nodeId.GetNamespaceURISpecified() {
		return ""
	}
	switch definition := nodeId.GetNodeId().(type) {
	case readWriteModel.NodeIdTwoByte:
		return fmt.Sprintf("ns=0;i=%d", definition.GetId())
	case readWriteModel.NodeIdFourByte:
		return fmt.Sprintf("ns=%d;i=%d", definition.GetNamespaceIndex(), definition.GetId())
	case readWriteModel.NodeIdNumeric:
		return fmt.Sprintf("ns=%d;i=%d", definition.GetNamespaceIndex(), definition.GetId())
	case readWriteModel.NodeIdString:
		value := definition.GetId().GetStringValue()
		if value == nil || *value == "" || strings.Contains(*value, ";") {
			return ""
		}
		return fmt.Sprintf("ns=%d;s=%s", definition.GetNamespaceIndex(), *value)
	case readWriteModel.NodeIdGuid:
		if len(definition.GetId()) != len(uuid.UUID{}) {
			return ""
		}
		guid := uuid.UUID(definition.GetId())
		// generateNodeId takes the GUID's bytes in this order back.
		return fmt.Sprintf("ns=%d;g=%s", definition.GetNamespaceIndex(), guid)
	default:
		return ""
	}
}

// tagAddress is the address of a tag, without a data type.
func tagAddress(tag Tag) string {
	return fmt.Sprintf("ns=%d;%s=%s", tag.GetNamespace(), tag.GetIdentifierType().GetValue(), tag.GetIdentifier())
}

func buildBrowseItem(reference readWriteModel.ReferenceDescription, address string, attributes nodeAttributes, children map[string]apiModel.PlcBrowseItem) apiModel.PlcBrowseItem {
	nodeClass := reference.GetNodeClass()
	isVariable := nodeClass == readWriteModel.NodeClass_nodeClassVariable
	browseName := ""
	if name := reference.GetBrowseName(); name != nil && name.GetName() != nil && name.GetName().GetStringValue() != nil {
		browseName = *name.GetName().GetStringValue()
	}
	name := browseName
	if displayName := reference.GetDisplayName(); displayName != nil && displayName.GetText() != nil && displayName.GetText().GetStringValue() != nil && *displayName.GetText().GetStringValue() != "" {
		name = *displayName.GetText().GetStringValue()
	}

	readable, writable := isVariable, isVariable
	dataType := readWriteModel.OpcuaDataType_NULL
	var arrayInfo []apiModel.ArrayInfo
	if isVariable && attributes.dataType != "" {
		readable, writable = attributes.readable, attributes.writable
		dataType = attributes.dataType
		arrayInfo = attributes.arrayInfo
	}
	tagParts := strings.SplitN(address, ";", 2)
	namespace := 0
	_, _ = fmt.Sscanf(tagParts[0], "ns=%d", &namespace)
	identifierType, _ := readWriteModel.OpcuaIdentifierTypeByValue(tagParts[1][:1])
	tag := &tag{namespace: namespace, identifier: tagParts[1][2:], identifierType: identifierType, dataType: dataType, arrayInfo: arrayInfo}

	options := map[string]apiValues.PlcValue{
		"node-class":  spiValues.NewPlcSTRING(strings.TrimPrefix(nodeClass.PLC4XEnumName(), "nodeClass")),
		"browse-name": spiValues.NewPlcSTRING(browseName),
	}
	dataTypeName := ""
	if dataType != readWriteModel.OpcuaDataType_NULL {
		dataTypeName = string(dataType)
		options["data-type"] = spiValues.NewPlcSTRING(dataTypeName)
	}
	return spiModel.NewDefaultPlcBrowseItem(tag, name, dataTypeName, readable, writable, isVariable, children, options)
}

// statusName names a status code, with its number.
func statusName(statusCode uint32) string {
	if status, ok := readWriteModel.OpcuaStatusCodeByValue(statusCode); ok {
		return fmt.Sprintf("%s (0x%08X)", status.PLC4XEnumName(), statusCode)
	}
	return fmt.Sprintf("0x%08X", statusCode)
}
