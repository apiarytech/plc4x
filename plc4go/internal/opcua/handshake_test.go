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
	"crypto/rand"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	readWriteModel "github.com/apache/plc4x/plc4go/protocols/opcua/readwrite/model"
	"github.com/apache/plc4x/plc4go/spi/testutils"
	"github.com/apache/plc4x/plc4go/spi/transports/test"
)

// testServer is the server side of an OPC UA connection over the in-memory transport, built
// from the same security code as the client but with the roles swapped. It knows the services
// of a handshake and GetEndpoints.
type testServer struct {
	t         *testing.T
	transport *test.TransportInstance
	identity  testIdentity
	security  *channelSecurity
	policy    *securityPolicy
	mode      readWriteModel.MessageSecurityMode
	// chunkBody is the largest body of a chunk the server sends; it splits larger responses.
	chunkBody int
	// advertised is the security policy and mode of the endpoint the server lists; by default
	// its own.
	advertisedPolicy *securityPolicy
	advertisedMode   readWriteModel.MessageSecurityMode

	mutex          sync.Mutex
	sequenceNumber int32
	tokenId        uint32
	sessionNonce   []byte
	clientNonce    []byte
	username       string
	password       string
	opened         []readWriteModel.SecurityTokenRequestType
	closed         bool
	services       []string
	failures       []error
}

func newTestServer(t *testing.T, transport *test.TransportInstance, policyName string, mode readWriteModel.MessageSecurityMode, identity testIdentity, client *x509.Certificate) *testServer {
	policy, err := securityPolicyByName(policyName)
	require.NoError(t, err)
	server := &testServer{t: t, transport: transport, identity: identity, policy: policy, mode: mode, sequenceNumber: 100, chunkBody: 1 << 20,
		advertisedPolicy: policy, advertisedMode: mode}
	server.security, err = newChannelSecurity(policy, mode, identity.key, identity.certificate.Raw, client)
	require.NoError(t, err)
	return server
}

func (s *testServer) fail(err error) {
	s.mutex.Lock()
	s.failures = append(s.failures, err)
	s.mutex.Unlock()
}

// serve answers what the client writes until ctx ends.
func (s *testServer) serve(ctx context.Context) {
	var written []byte
	for ctx.Err() == nil {
		written = append(written, s.transport.DrainWriteBuffer(s.transport.GetNumDrainableBytes())...)
		for len(written) >= 8 {
			size := int(binary.LittleEndian.Uint32(written[4:8]))
			if len(written) < size {
				break
			}
			chunk := append([]byte(nil), written[:size]...)
			written = written[size:]
			if err := s.handle(chunk); err != nil {
				s.fail(err)
			}
		}
		time.Sleep(2 * time.Millisecond)
	}
}

func (s *testServer) send(apu readWriteModel.OpcuaAPU, asymmetric bool) error {
	chunk, err := apu.Serialize()
	if err != nil {
		return err
	}
	if asymmetric {
		chunk, err = s.security.secureAsymmetric(chunk)
	} else {
		chunk, err = s.security.secureSymmetric(chunk)
	}
	if err != nil {
		return err
	}
	s.transport.FillReadBuffer(chunk)
	return nil
}

func (s *testServer) nextSequenceNumber() int32 {
	s.sequenceNumber++
	return s.sequenceNumber
}

func (s *testServer) handle(chunk []byte) error {
	switch string(chunk[0:3]) {
	case "HEL":
		ack := readWriteModel.NewOpcuaAPU(readWriteModel.NewOpcuaAcknowledgeResponse(readWriteModel.ChunkType_FINAL, VERSION,
			readWriteModel.NewOpcuaProtocolLimits(65535, 65535, 0, 0)))
		bytes, err := ack.Serialize()
		if err != nil {
			return err
		}
		s.transport.FillReadBuffer(bytes)
		return nil
	case "OPN":
		opened, err := s.security.openAsymmetric(chunk)
		if err != nil {
			return err
		}
		apu, err := readWriteModel.OpcuaAPUParse(context.Background(), opened, false, true)
		if err != nil {
			return err
		}
		payload := apu.GetMessage().(readWriteModel.OpcuaOpenRequest).GetMessage().(readWriteModel.BinaryPayload)
		body, err := parseExtensionObject(context.Background(), payload.GetPayload())
		if err != nil {
			return err
		}
		request := body.(readWriteModel.OpenSecureChannelRequest)
		s.mutex.Lock()
		s.opened = append(s.opened, request.GetRequestType())
		s.tokenId++
		tokenId := s.tokenId
		s.mutex.Unlock()
		serverNonce, err := s.security.newLocalNonce()
		if err != nil {
			return err
		}
		response := readWriteModel.NewOpenSecureChannelResponse(s.responseHeader(0), VERSION,
			readWriteModel.NewChannelSecurityToken(7, tokenId, 0, 3600000), byteString(serverNonce))
		buffer, err := serializeExtensionObject(context.Background(), response)
		if err != nil {
			return err
		}
		uri := s.policy.uri
		if err := s.send(readWriteModel.NewOpcuaAPU(readWriteModel.NewOpcuaOpenResponse(readWriteModel.ChunkType_FINAL,
			readWriteModel.NewOpenChannelMessageResponse(7, readWriteModel.NewPascalString(&uri),
				byteString(s.security.localCertificateIfSecured()), byteString(s.security.remoteThumbprintIfSecured())),
			readWriteModel.NewBinaryPayload(readWriteModel.NewSequenceHeader(s.nextSequenceNumber(), payload.GetSequenceHeader().GetRequestId()), buffer.GetBytes()),
		)), true); err != nil {
			return err
		}
		var clientNonce []byte
		if nonce := request.GetClientNonce(); nonce != nil {
			clientNonce = nonce.GetStringValue()
		}
		return s.security.installToken(tokenId, clientNonce)
	case "CLO":
		if _, err := s.security.openSymmetric(chunk); err != nil {
			return err
		}
		s.mutex.Lock()
		s.closed = true
		s.mutex.Unlock()
		return nil
	case "MSG":
		opened, err := s.security.openSymmetric(chunk)
		if err != nil {
			return err
		}
		apu, err := readWriteModel.OpcuaAPUParse(context.Background(), opened, false, true)
		if err != nil {
			return err
		}
		payload := apu.GetMessage().(readWriteModel.OpcuaMessageRequest).GetMessage().(readWriteModel.BinaryPayload)
		body, err := parseExtensionObject(context.Background(), payload.GetPayload())
		if err != nil {
			return err
		}
		response, err := s.service(body)
		if err != nil {
			return err
		}
		return s.respond(payload.GetSequenceHeader().GetRequestId(), response)
	}
	return nil
}

// respond sends a service response, in chunks of at most chunkBody bytes of body.
func (s *testServer) respond(requestId int32, response readWriteModel.ExtensionObjectDefinition) error {
	buffer, err := serializeExtensionObject(context.Background(), response)
	if err != nil {
		return err
	}
	body := buffer.GetBytes()
	for start := 0; start == 0 || start < len(body); start += s.chunkBody {
		end := min(start+s.chunkBody, len(body))
		chunkType := readWriteModel.ChunkType_CONTINUE
		if end == len(body) {
			chunkType = readWriteModel.ChunkType_FINAL
		}
		if err := s.send(readWriteModel.NewOpcuaAPU(readWriteModel.NewOpcuaMessageResponse(chunkType,
			readWriteModel.NewSecurityHeader(7, s.tokenId),
			readWriteModel.NewBinaryPayload(readWriteModel.NewSequenceHeader(s.nextSequenceNumber(), requestId), body[start:end]),
		)), false); err != nil {
			return err
		}
	}
	return nil
}

func (s *testServer) responseHeader(requestHandle uint32) readWriteModel.ResponseHeader {
	return readWriteModel.NewResponseHeader(0, requestHandle, readWriteModel.NewStatusCode(0),
		readWriteModel.NewDiagnosticInfo(false, false, false, false, false, false, false, nil, nil, nil, nil, nil, nil, nil),
		nil, NULL_EXTENSION_OBJECT)
}

func (s *testServer) endpoints() []readWriteModel.EndpointDescription {
	uri := s.advertisedPolicy.uri
	tokenPolicyUri := s.advertisedPolicy.uri
	return []readWriteModel.EndpointDescription{readWriteModel.NewEndpointDescription(
		stringOf("opc.tcp://test:4840"),
		readWriteModel.NewApplicationDescription(stringOf("urn:test:server"), stringOf("urn:test"),
			readWriteModel.NewLocalizedText(true, true, stringOf("en"), stringOf("test")),
			readWriteModel.ApplicationType_applicationTypeServer, NULL_STRING, NULL_STRING, nil),
		byteString(s.identity.certificate.Raw),
		s.advertisedMode,
		readWriteModel.NewPascalString(&uri),
		[]readWriteModel.UserTokenPolicy{
			readWriteModel.NewUserTokenPolicy(stringOf("anonymous"), readWriteModel.UserTokenType_userTokenTypeAnonymous, NULL_STRING, NULL_STRING, NULL_STRING),
			readWriteModel.NewUserTokenPolicy(stringOf("username"), readWriteModel.UserTokenType_userTokenTypeUserName, NULL_STRING, NULL_STRING, stringOf(tokenPolicyUri)),
		},
		stringOf("http://opcfoundation.org/UA-Profile/Transport/uatcp-uasc-uabinary"),
		0,
	)}
}

func (s *testServer) service(request readWriteModel.ExtensionObjectDefinition) (readWriteModel.ExtensionObjectDefinition, error) {
	s.mutex.Lock()
	s.services = append(s.services, fmt.Sprintf("%T", request))
	s.mutex.Unlock()
	switch request := request.(type) {
	case readWriteModel.GetEndpointsRequest:
		return readWriteModel.NewGetEndpointsResponse(s.responseHeader(request.GetRequestHeader().GetRequestHandle()), s.endpoints()), nil
	case readWriteModel.CreateSessionRequest:
		s.clientNonce = request.GetClientNonce().GetStringValue()
		s.sessionNonce = make([]byte, 32)
		_, _ = rand.Read(s.sessionNonce)
		algorithm, signature, err := s.security.signSession(s.clientNonce)
		if err != nil {
			return nil, err
		}
		if s.security.secured() && string(request.GetClientCertificate().GetStringValue()) != string(s.security.remoteCertificate.Raw) {
			s.fail(errAssert("CreateSession carries another client certificate"))
		}
		return readWriteModel.NewCreateSessionResponse(s.responseHeader(request.GetRequestHeader().GetRequestHandle()),
			readWriteModel.NewNodeId(readWriteModel.NewNodeIdNumeric(1, 1000)),
			readWriteModel.NewNodeId(readWriteModel.NewNodeIdNumeric(1, 2000)),
			120000, byteString(s.sessionNonce), byteString(s.identity.certificate.Raw), s.endpoints(), nil,
			readWriteModel.NewSignatureData(stringOf(algorithm), byteString(signature)), 0), nil
	case readWriteModel.ActivateSessionRequest:
		if s.security.secured() {
			signature := request.GetClientSignature()
			if err := s.security.verifySession(s.sessionNonce, *signature.GetAlgorithm().GetStringValue(), signature.GetSignature().GetStringValue()); err != nil {
				s.fail(err)
			}
		}
		if token, ok := request.GetUserIdentityToken().GetBody().(readWriteModel.UserNameIdentityToken); ok {
			s.username = *token.GetUserName().GetStringValue()
			password := token.GetPassword().GetStringValue()
			if algorithm := token.GetEncryptionAlgorithm(); algorithm != nil && algorithm.GetStringValue() != nil {
				var plain []byte
				for start := 0; start < len(password); start += s.identity.key.Size() {
					block, err := s.policy.asymmetricDecrypt(s.identity.key, password[start:start+s.identity.key.Size()])
					if err != nil {
						return nil, err
					}
					plain = append(plain, block...)
				}
				length := int(binary.LittleEndian.Uint32(plain))
				password = plain[4 : 4+length-len(s.sessionNonce)]
				if string(plain[4+length-len(s.sessionNonce):4+length]) != string(s.sessionNonce) {
					s.fail(errAssert("password is not followed by the session nonce"))
				}
			}
			s.password = string(password)
		}
		return readWriteModel.NewActivateSessionResponse(s.responseHeader(request.GetRequestHeader().GetRequestHandle()), byteString(nil), nil, nil), nil
	case readWriteModel.CloseSessionRequest:
		return readWriteModel.NewCloseSessionResponse(s.responseHeader(request.GetRequestHeader().GetRequestHandle())), nil
	}
	return nil, errAssert("unexpected request")
}

type errAssert string

func (e errAssert) Error() string { return string(e) }

type handshakeRig struct {
	channel    *SecureChannel
	connection *Connection
	server     *testServer
}

// newHandshakeRig connects a channel with the configuration to a test server with the policy
// and mode, whose certificate is serverIdentity; the channel expects expectedServer.
func newHandshakeRig(t *testing.T, configuration Configuration, serverIdentity testIdentity, expectedServer *x509.Certificate) *handshakeRig {
	_options := testutils.EnrichOptionsWithOptionsForTesting(t)
	transportInstance, err := test.NewTransport(_options...).CreateTransportInstance(url.URL{Scheme: "test"}, nil, _options...)
	require.NoError(t, err)
	testTransport := transportInstance.(*test.TransportInstance)
	codec := NewMessageCodec(testTransport, _options...)
	require.NoError(t, codec.Connect(testutils.TestContext(t)))
	t.Cleanup(func() { _ = codec.Disconnect() })

	client := identityForTest(t, "client", 2048)
	mode, err := configuration.messageSecurityMode()
	require.NoError(t, err)
	server := newTestServer(t, testTransport, configuration.SecurityPolicy, mode, serverIdentity, client.certificate)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		server.serve(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})

	configuration.Endpoint = "opc.tcp://test:4840"
	channel := NewSecureChannel(zerolog.Nop(), DriverContext{}, configuration)
	policy, err := configuration.securityPolicy()
	require.NoError(t, err)
	if policy.isNone() {
		require.NoError(t, channel.prepareSecurity(clientIdentity{}, nil))
	} else {
		require.NoError(t, channel.prepareSecurity(clientIdentity{key: client.key, certificate: client.certificate.Raw}, expectedServer))
	}
	t.Cleanup(channel.stopRenewal)
	return &handshakeRig{channel: channel, connection: &Connection{messageCodec: codec}, server: server}
}

func (r *handshakeRig) connect(t *testing.T) error {
	ctx, cancel := context.WithTimeout(testutils.TestContext(t), 20*time.Second)
	defer cancel()
	return r.channel.onConnect(ctx, r.connection)
}

func (r *handshakeRig) serverFailures() []error {
	r.server.mutex.Lock()
	defer r.server.mutex.Unlock()
	return append([]error(nil), r.server.failures...)
}

func TestHandshake(t *testing.T) {
	serverIdentity := identityForTest(t, "server", 2048)
	tests := []struct {
		name     string
		policy   string
		mode     string
		username string
	}{
		{name: "None anonymous", policy: "None"},
		{name: "Basic256Sha256 SignAndEncrypt username", policy: "Basic256Sha256", mode: "SIGN_ENCRYPT", username: "operator"},
		{name: "Basic256Sha256 Sign anonymous", policy: "Basic256Sha256", mode: "SIGN"},
		{name: "Aes128_Sha256_RsaOaep SignAndEncrypt username", policy: "Aes128_Sha256_RsaOaep", mode: "SIGN_ENCRYPT", username: "operator"},
		{name: "Aes256_Sha256_RsaPss SignAndEncrypt username", policy: "Aes256_Sha256_RsaPss", mode: "SIGN_ENCRYPT", username: "operator"},
		{name: "Basic256 Sign username", policy: "Basic256", mode: "SIGN", username: "operator"},
		{name: "Basic128Rsa15 SignAndEncrypt username", policy: "Basic128Rsa15", mode: "SIGN_ENCRYPT", username: "operator"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			configuration := createDefaultConfiguration()
			configuration.SecurityPolicy = tt.policy
			configuration.MessageSecurity = tt.mode
			configuration.Username = tt.username
			configuration.Password = "secret password"
			rig := newHandshakeRig(t, configuration, serverIdentity, serverIdentity.certificate)

			require.NoError(t, rig.connect(t))
			assert.Empty(t, rig.serverFailures())
			assert.Equal(t, tt.username, rig.server.username)
			if tt.username != "" {
				assert.Equal(t, "secret password", rig.server.password, "the server decrypts the password")
			}

			// The session works: a large response comes back in encrypted chunks.
			rig.server.chunkBody = 200
			ctx, cancel := context.WithTimeout(testutils.TestContext(t), 10*time.Second)
			defer cancel()
			response, err := rig.channel.call(ctx, rig.connection.messageCodec, readWriteModel.NewGetEndpointsRequest(
				rig.channel.newRequestHeader(rig.channel.getRequestHandle()), rig.channel.endpoint, nil, nil))
			require.NoError(t, err)
			assert.Len(t, response.(readWriteModel.GetEndpointsResponse).GetEndpoints(), 1)

			// The token is renewed, and the session goes on with the new keys.
			require.NoError(t, rig.channel.openChannel(ctx, rig.connection.messageCodec, readWriteModel.SecurityTokenRequestType_securityTokenRequestTypeRenew))
			assert.Equal(t, uint32(2), rig.channel.tokenId.Load())
			_, err = rig.channel.call(ctx, rig.connection.messageCodec, readWriteModel.NewGetEndpointsRequest(
				rig.channel.newRequestHeader(rig.channel.getRequestHandle()), rig.channel.endpoint, nil, nil))
			require.NoError(t, err)

			rig.channel.onDisconnect(ctx, rig.connection)
			require.Eventually(t, func() bool {
				rig.server.mutex.Lock()
				defer rig.server.mutex.Unlock()
				return rig.server.closed || len(rig.server.failures) > 0
			}, 5*time.Second, 10*time.Millisecond, "CloseSecureChannel arrives")
			require.Empty(t, rig.serverFailures())
			assert.True(t, rig.server.closed, "CloseSecureChannel arrives")
			assert.Equal(t, []readWriteModel.SecurityTokenRequestType{
				readWriteModel.SecurityTokenRequestType_securityTokenRequestTypeIssue,
				readWriteModel.SecurityTokenRequestType_securityTokenRequestTypeRenew,
			}, rig.server.opened)
			assert.Empty(t, rig.serverFailures())
		})
	}
}

// A server with another certificate than the one the client expects cannot open the channel.
func TestHandshakeRefusesAnotherServer(t *testing.T) {
	impostor := identityForTest(t, "impostor", 2048)
	expected := identityForTest(t, "server", 2048)
	configuration := createDefaultConfiguration()
	configuration.SecurityPolicy = "Basic256Sha256"
	rig := newHandshakeRig(t, configuration, impostor, expected.certificate)
	assert.Error(t, rig.connect(t))
}

// Without encryption a password is refused unless explicitly allowed.
func TestHandshakeRefusesAnUnencryptedPassword(t *testing.T) {
	serverIdentity := identityForTest(t, "server", 2048)
	configuration := createDefaultConfiguration()
	configuration.Username = "operator"
	configuration.Password = "secret"
	rig := newHandshakeRig(t, configuration, serverIdentity, nil)
	// The test server's username policy names the None policy: the password would go in clear.
	assert.ErrorContains(t, rig.connect(t), "unencrypted")
}

// Discovery asks an unsecured channel for the endpoints and returns the certificate of the
// endpoint with the configured policy and mode.
func TestDiscoverServerCertificate(t *testing.T) {
	serverIdentity := identityForTest(t, "server", 2048)
	_options := testutils.EnrichOptionsWithOptionsForTesting(t)
	transportInstance, err := test.NewTransport(_options...).CreateTransportInstance(url.URL{Scheme: "test"}, nil, _options...)
	require.NoError(t, err)
	testTransport := transportInstance.(*test.TransportInstance)
	codec := NewMessageCodec(testTransport, _options...)

	server := newTestServer(t, testTransport, "None", readWriteModel.MessageSecurityMode_messageSecurityModeNone, serverIdentity, nil)
	server.advertisedPolicy, _ = securityPolicyByName("Basic256Sha256")
	server.advertisedMode = readWriteModel.MessageSecurityMode_messageSecurityModeSignAndEncrypt
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		server.serve(ctx)
	}()
	defer func() {
		cancel()
		<-done
	}()

	configuration := createDefaultConfiguration()
	configuration.SecurityPolicy = "Basic256Sha256"
	configuration.Endpoint = "opc.tcp://test:4840"
	chain, err := discoverServerCertificate(testutils.TestContext(t), zerolog.Nop(), configuration, codec)
	require.NoError(t, err)
	require.Len(t, chain, 1)
	assert.True(t, chain[0].Equal(serverIdentity.certificate))
	assert.Empty(t, server.failures)

	configuration.MessageSecurity = "SIGN"
	_, err = discoverServerCertificate(testutils.TestContext(t), zerolog.Nop(), configuration, NewMessageCodec(testTransport, _options...))
	assert.ErrorContains(t, err, "no endpoint with security policy Basic256Sha256")
}
