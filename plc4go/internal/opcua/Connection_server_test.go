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

// Runs the driver against a real OPC UA server when OPCUA_TEST_ENDPOINT names one (host:port).
// tools/opcua-peer runs two servers written independently of plc4x, open62541 and asyncua, in
// Docker, each with the address space below (ns=2, the namespace urn:plc4x:test):
//
//	Demo                    folder
//	Demo.Bool .. Demo.String  read-only scalars: true, -1234, 42, -9000000000, 4000000000, 3.5,
//	                        2.718281828459045, "hello"
//	Demo.Int32Array         [1, 2, 3]
//	Demo.Counter            Int32, counts up every 100 ms
//	Demo.ReadOnly           Int32 7, not writable
//	Demo.Writable*          Int32, Double, Boolean and String, writable by operator/secret
//
// OPCUA_TEST_SERVER_CERTIFICATE pins the server's certificate for the secured channels; without
// it they are skipped.

import (
	"context"
	"fmt"
	"math/rand/v2"
	"net/url"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	plc4go "github.com/apache/plc4x/plc4go/pkg/api"
	apiModel "github.com/apache/plc4x/plc4go/pkg/api/model"
	"github.com/apache/plc4x/plc4go/pkg/api/transports"
	"github.com/apache/plc4x/plc4go/spi/options/converter"
	"github.com/apache/plc4x/plc4go/spi/testutils"
)

func serverEndpoint(t *testing.T) string {
	endpoint := os.Getenv("OPCUA_TEST_ENDPOINT")
	if endpoint == "" {
		t.Skip("set OPCUA_TEST_ENDPOINT to host:port of an OPC UA server with the test address space (tools/opcua-peer)")
	}
	return endpoint
}

// connectToServer connects with the given connection-string options. Each connection gets a
// certificate directory of its own.
func connectToServer(t *testing.T, options url.Values) (plc4go.PlcConnection, error) {
	endpoint := serverEndpoint(t)
	if options.Get("cert-directory") == "" {
		options.Set("cert-directory", t.TempDir())
	}
	optionsForTesting := testutils.EnrichOptionsWithOptionsForTesting(t)
	driverManager := plc4go.NewPlcDriverManager(converter.WithOptionToExternal(optionsForTesting...)...)
	t.Cleanup(func() { _ = driverManager.Close() })
	driverManager.RegisterDriver(NewDriver(optionsForTesting...))
	transports.RegisterTcpTransport(driverManager, converter.WithOptionToExternal(optionsForTesting...)...)
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	connection, err := driverManager.GetConnection(ctx, fmt.Sprintf("opcua:tcp://%s?%s", endpoint, options.Encode()))
	if err != nil {
		return nil, err
	}
	t.Cleanup(func() { _ = connection.Close() })
	return connection, nil
}

func mustConnectToServer(t *testing.T, options url.Values) plc4go.PlcConnection {
	connection, err := connectToServer(t, options)
	require.NoError(t, err)
	require.True(t, connection.IsConnected())
	return connection
}

func readTags(t *testing.T, connection plc4go.PlcConnection, tags map[string]string) apiModel.PlcReadResponse {
	builder := connection.ReadRequestBuilder()
	for name, address := range tags {
		builder.AddTagAddress(name, address)
	}
	request, err := builder.Build()
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	result := <-request.Execute(ctx)
	require.NoError(t, result.GetErr())
	return result.GetResponse()
}

func writeTag(t *testing.T, connection plc4go.PlcConnection, address string, value any) apiModel.PlcResponseCode {
	request, err := connection.WriteRequestBuilder().AddTagAddress("v", address, value).Build()
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	result := <-request.Execute(ctx)
	require.NoError(t, result.GetErr())
	return result.GetResponse().GetResponseCode("v")
}

func operator() url.Values {
	return url.Values{"username": {"operator"}, "password": {"secret"}}
}

func TestServerReadsEveryType(t *testing.T) {
	connection := mustConnectToServer(t, url.Values{})
	response := readTags(t, connection, map[string]string{
		"bool":   "ns=2;s=Demo.Bool;BOOL",
		"int16":  "ns=2;s=Demo.Int16;INT",
		"int32":  "ns=2;s=Demo.Int32;DINT",
		"int64":  "ns=2;s=Demo.Int64;LINT",
		"uint32": "ns=2;s=Demo.UInt32;UDINT",
		"float":  "ns=2;s=Demo.Float;REAL",
		"double": "ns=2;s=Demo.Double;LREAL",
		"string": "ns=2;s=Demo.String;STRING",
		"array":  "ns=2;s=Demo.Int32Array;DINT",
		// Without a data type the driver takes the server's.
		"untyped": "ns=2;s=Demo.Int32",
	})
	for _, name := range response.GetTagNames() {
		require.Equal(t, apiModel.PlcResponseCode_OK, response.GetResponseCode(name), name)
	}
	assert.True(t, response.GetValue("bool").GetBool())
	assert.EqualValues(t, -1234, response.GetValue("int16").GetInt16())
	assert.EqualValues(t, 42, response.GetValue("int32").GetInt32())
	assert.EqualValues(t, -9000000000, response.GetValue("int64").GetInt64())
	assert.EqualValues(t, 4000000000, response.GetValue("uint32").GetUint32())
	assert.EqualValues(t, 3.5, response.GetValue("float").GetFloat32())
	assert.EqualValues(t, 2.718281828459045, response.GetValue("double").GetFloat64())
	assert.Equal(t, "hello", response.GetValue("string").GetString())
	array := response.GetValue("array")
	require.True(t, array.IsList(), "an array reads as a list: %v", array)
	require.Len(t, array.GetList(), 3)
	for i, element := range array.GetList() {
		assert.EqualValues(t, i+1, element.GetInt32())
	}
	assert.EqualValues(t, 42, response.GetValue("untyped").GetInt32())
}

func TestServerReadOfAMissingNode(t *testing.T) {
	connection := mustConnectToServer(t, url.Values{})
	response := readTags(t, connection, map[string]string{"missing": "ns=2;s=Demo.Nowhere;DINT"})
	assert.Equal(t, apiModel.PlcResponseCode_NOT_FOUND, response.GetResponseCode("missing"))
}

func TestServerBrowse(t *testing.T) {
	connection := mustConnectToServer(t, url.Values{})
	request, err := connection.BrowseRequestBuilder().AddQuery("demo", "ns=2;s=Demo").Build()
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	result := <-request.Execute(ctx)
	require.NoError(t, result.GetErr())
	require.Equal(t, apiModel.PlcResponseCode_OK, result.GetResponse().GetResponseCode("demo"))
	items := map[string]apiModel.PlcBrowseItem{}
	for _, item := range result.GetResponse().GetQueryResults("demo") {
		items[item.GetName()] = item
	}
	for _, name := range []string{"Bool", "Int16", "Int32", "Int64", "UInt32", "Float", "Double", "String", "Int32Array", "Counter", "ReadOnly", "WritableInt32", "WritableDouble", "WritableBool", "WritableString"} {
		assert.Contains(t, items, name)
	}
	if item, ok := items["Double"]; ok {
		assert.Equal(t, "ns=2;s=Demo.Double;LREAL", item.GetTag().GetAddressString())
		assert.True(t, item.IsReadable())
	}
	if item, ok := items["Int32Array"]; ok {
		require.Len(t, item.GetTag().GetArrayInfo(), 1)
		assert.EqualValues(t, 3, item.GetTag().GetArrayInfo()[0].GetSize())
	}
	if item, ok := items["ReadOnly"]; ok {
		assert.False(t, item.IsWritable())
	}
	if item, ok := items["WritableInt32"]; ok {
		assert.True(t, item.IsWritable())
	}
}

func TestServerSubscribe(t *testing.T) {
	connection := mustConnectToServer(t, url.Values{})
	var mutex sync.Mutex
	var values []int32
	request, err := connection.SubscriptionRequestBuilder().
		AddChangeOfStateTagAddress("counter", "ns=2;s=Demo.Counter;DINT").
		AddPreRegisteredConsumer("counter", func(event apiModel.PlcSubscriptionEvent) {
			if event.GetResponseCode("counter") != apiModel.PlcResponseCode_OK {
				return
			}
			mutex.Lock()
			defer mutex.Unlock()
			values = append(values, event.GetValue("counter").GetInt32())
		}).Build()
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	result := <-request.Execute(ctx)
	require.NoError(t, result.GetErr())
	require.Equal(t, apiModel.PlcResponseCode_OK, result.GetResponse().GetResponseCode("counter"))
	require.Eventually(t, func() bool {
		mutex.Lock()
		defer mutex.Unlock()
		return len(values) >= 5
	}, 10*time.Second, 50*time.Millisecond, "the counter changes every 100 ms")
	mutex.Lock()
	defer mutex.Unlock()
	for i := 1; i < len(values); i++ {
		assert.Greater(t, values[i], values[i-1], "values arrive in order: %v", values)
	}
}

func TestServerWrite(t *testing.T) {
	connection := mustConnectToServer(t, operator())
	number := rand.Int32N(1_000_000)
	assert.Equal(t, apiModel.PlcResponseCode_OK, writeTag(t, connection, "ns=2;s=Demo.WritableInt32;DINT", number))
	assert.Equal(t, apiModel.PlcResponseCode_OK, writeTag(t, connection, "ns=2;s=Demo.WritableDouble;LREAL", 0.1+float64(number)))
	assert.Equal(t, apiModel.PlcResponseCode_OK, writeTag(t, connection, "ns=2;s=Demo.WritableBool;BOOL", true))
	text := fmt.Sprintf("written %d", number)
	assert.Equal(t, apiModel.PlcResponseCode_OK, writeTag(t, connection, "ns=2;s=Demo.WritableString;STRING", text))

	response := readTags(t, connection, map[string]string{
		"int32":  "ns=2;s=Demo.WritableInt32;DINT",
		"double": "ns=2;s=Demo.WritableDouble;LREAL",
		"bool":   "ns=2;s=Demo.WritableBool;BOOL",
		"string": "ns=2;s=Demo.WritableString;STRING",
	})
	assert.Equal(t, number, response.GetValue("int32").GetInt32())
	assert.Equal(t, 0.1+float64(number), response.GetValue("double").GetFloat64())
	assert.True(t, response.GetValue("bool").GetBool())
	assert.Equal(t, text, response.GetValue("string").GetString())

	assert.Equal(t, apiModel.PlcResponseCode_ACCESS_DENIED, writeTag(t, connection, "ns=2;s=Demo.ReadOnly;DINT", int32(8)), "not writable")
	// open62541 answers BadNodeIdUnknown, asyncua BadUserAccessDenied.
	assert.Contains(t, []apiModel.PlcResponseCode{apiModel.PlcResponseCode_NOT_FOUND, apiModel.PlcResponseCode_ACCESS_DENIED},
		writeTag(t, connection, "ns=2;s=Demo.Nowhere;DINT", int32(8)))
}

func TestServerRefusesAWrongPassword(t *testing.T) {
	_, err := connectToServer(t, url.Values{"username": {"operator"}, "password": {"wrong"}})
	assert.Error(t, err)
}

// Every security policy both servers have, signed and encrypted, logged in as operator.
func TestServerSecureChannels(t *testing.T) {
	certificate := os.Getenv("OPCUA_TEST_SERVER_CERTIFICATE")
	serverEndpoint(t)
	if certificate == "" {
		t.Skip("set OPCUA_TEST_SERVER_CERTIFICATE to the server's certificate to test the secured channels")
	}
	for _, policy := range []string{"Basic256Sha256", "Aes128_Sha256_RsaOaep", "Aes256_Sha256_RsaPss"} {
		for _, mode := range []string{"SIGN", "SIGN_ENCRYPT"} {
			t.Run(policy+"/"+mode, func(t *testing.T) {
				options := operator()
				options.Set("security-policy", policy)
				options.Set("message-security", mode)
				options.Set("server-certificate-file", certificate)
				connection := mustConnectToServer(t, options)
				response := readTags(t, connection, map[string]string{"int32": "ns=2;s=Demo.Int32;DINT"})
				require.Equal(t, apiModel.PlcResponseCode_OK, response.GetResponseCode("int32"))
				assert.EqualValues(t, 42, response.GetValue("int32").GetInt32())

				number := rand.Int32N(1_000_000)
				require.Equal(t, apiModel.PlcResponseCode_OK, writeTag(t, connection, "ns=2;s=Demo.WritableInt32;DINT", number))
				response = readTags(t, connection, map[string]string{"int32": "ns=2;s=Demo.WritableInt32;DINT"})
				assert.Equal(t, number, response.GetValue("int32").GetInt32())
			})
		}
	}
}

// A server whose certificate is not the pinned one is refused.
func TestServerRefusesAnotherCertificate(t *testing.T) {
	serverEndpoint(t)
	other := identityForTest(t, "impostor", 2048)
	file := t.TempDir() + "/other.der"
	require.NoError(t, os.WriteFile(file, other.certificate.Raw, 0o600))
	options := operator()
	options.Set("security-policy", "Basic256Sha256")
	options.Set("message-security", "SIGN_ENCRYPT")
	options.Set("server-certificate-file", file)
	_, err := connectToServer(t, options)
	assert.Error(t, err)
}
