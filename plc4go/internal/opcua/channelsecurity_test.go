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
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	readWriteModel "github.com/apache/plc4x/plc4go/protocols/opcua/readwrite/model"
)

// The TLS 1.2 PRF test vector for SHA-256: P_SHA256 of the secret, with "test label" followed
// by the seed as its seed.
func TestPHashSha256(t *testing.T) {
	secret, _ := hex.DecodeString("9bbe436ba940f017b17652849a71db35")
	seed, _ := hex.DecodeString("a0ba9f936cda311827a6f796ffd5198c")
	want, _ := hex.DecodeString("e3f229ba727be17b8d122620557cd453c2aab21d07c3d495329b52d4e61edb5a" +
		"6b301791e90d35c9c9a46b4e14baf9af0fa022f7077def17abfd3797c0564bab" +
		"4fbc91666e9def9b97fce34f796789baa48082d122ee42c5a72e5a5110fff701" +
		"87347b66")
	got := pHash(sha256.New, secret, append([]byte("test label"), seed...), len(want))
	assert.Equal(t, hex.EncodeToString(want), hex.EncodeToString(got))
}

func TestSecurityPolicyByName(t *testing.T) {
	for _, name := range []string{"None", "Basic128Rsa15", "Basic256", "Basic256Sha256", "Aes128_Sha256_RsaOaep", "Aes256_Sha256_RsaPss"} {
		policy, err := securityPolicyByName(name)
		require.NoError(t, err, name)
		assert.Equal(t, SECURITY_POLICY_URI_PREFIX+name, policy.uri)
		byUri, err := securityPolicyByName(policy.uri)
		require.NoError(t, err)
		assert.Same(t, policy, byUri)
	}
	policy, err := securityPolicyByName("basic256sha256")
	require.NoError(t, err)
	assert.Equal(t, "Basic256Sha256", policy.name)
	_, err = securityPolicyByName("Basic512")
	assert.ErrorContains(t, err, "unknown security-policy")
}

type testIdentity struct {
	key         *rsa.PrivateKey
	certificate *x509.Certificate
}

var (
	testIdentitiesMutex sync.Mutex
	testIdentities      = map[string]testIdentity{}
)

// identityForTest makes (once per name and size) an RSA key and a self-signed certificate.
func identityForTest(t *testing.T, name string, bits int) testIdentity {
	testIdentitiesMutex.Lock()
	defer testIdentitiesMutex.Unlock()
	key := fmt.Sprintf("%s/%d", name, bits)
	if identity, ok := testIdentities[key]; ok {
		return identity
	}
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	require.NoError(t, err)
	certificate, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	identity := testIdentity{key: privateKey, certificate: certificate}
	testIdentities[key] = identity
	return identity
}

// channelPair builds a client's and a server's view of one channel.
func channelPair(t *testing.T, policyName string, mode readWriteModel.MessageSecurityMode, clientBits, serverBits int) (client, server *channelSecurity) {
	policy, err := securityPolicyByName(policyName)
	require.NoError(t, err)
	clientIdentity := identityForTest(t, "client", clientBits)
	serverIdentity := identityForTest(t, "server", serverBits)
	client, err = newChannelSecurity(policy, mode, clientIdentity.key, clientIdentity.certificate.Raw, serverIdentity.certificate)
	require.NoError(t, err)
	server, err = newChannelSecurity(policy, mode, serverIdentity.key, serverIdentity.certificate.Raw, clientIdentity.certificate)
	require.NoError(t, err)
	return client, server
}

func openChunk(t *testing.T, sender *channelSecurity, response bool, body []byte) []byte {
	payload := readWriteModel.NewBinaryPayload(readWriteModel.NewSequenceHeader(51, 7), body)
	certificate := NULL_BYTE_STRING
	if len(sender.localCertificate) > 0 {
		certificate = readWriteModel.NewPascalByteString(int32(len(sender.localCertificate)), sender.localCertificate)
	}
	thumbprint := NULL_BYTE_STRING
	if remote := sender.remoteThumbprint(); remote != nil {
		thumbprint = readWriteModel.NewPascalByteString(int32(len(remote)), remote)
	}
	uri := sender.policy.uri
	var message readWriteModel.MessagePDU
	if response {
		message = readWriteModel.NewOpcuaOpenResponse(readWriteModel.ChunkType_FINAL,
			readWriteModel.NewOpenChannelMessageResponse(9, readWriteModel.NewPascalString(&uri), certificate, thumbprint), payload)
	} else {
		message = readWriteModel.NewOpcuaOpenRequest(readWriteModel.ChunkType_FINAL,
			readWriteModel.NewOpenChannelMessageRequest(9, readWriteModel.NewPascalString(&uri), certificate, thumbprint), payload)
	}
	chunk, err := readWriteModel.NewOpcuaAPU(message).Serialize()
	require.NoError(t, err)
	return chunk
}

func messageChunk(t *testing.T, body []byte) []byte {
	chunk, err := readWriteModel.NewOpcuaAPU(readWriteModel.NewOpcuaMessageRequest(readWriteModel.ChunkType_FINAL,
		readWriteModel.NewSecurityHeader(9, 0),
		readWriteModel.NewBinaryPayload(readWriteModel.NewSequenceHeader(52, 8), body))).Serialize()
	require.NoError(t, err)
	return chunk
}

var testModes = []struct {
	name string
	mode readWriteModel.MessageSecurityMode
}{
	{"Sign", readWriteModel.MessageSecurityMode_messageSecurityModeSign},
	{"SignAndEncrypt", readWriteModel.MessageSecurityMode_messageSecurityModeSignAndEncrypt},
}

func TestAsymmetricRoundTrip(t *testing.T) {
	for _, policy := range securityPolicies[1:] {
		for _, size := range []struct{ client, server int }{{2048, 2048}, {2048, 4096}, {4096, 2048}} {
			t.Run(fmt.Sprintf("%s/%d-%d", policy.name, size.client, size.server), func(t *testing.T) {
				client, server := channelPair(t, policy.name, readWriteModel.MessageSecurityMode_messageSecurityModeSignAndEncrypt, size.client, size.server)
				for _, length := range []int{0, 1, 100, 1000} {
					body := make([]byte, length)
					_, _ = rand.Read(body)

					request := openChunk(t, client, false, body)
					secured, err := client.secureAsymmetric(request)
					require.NoError(t, err)
					assert.Equal(t, uint32(len(secured)), binary.LittleEndian.Uint32(secured[4:8]), "size field")
					opened, err := server.openAsymmetric(secured)
					require.NoError(t, err, "length %d", length)
					assert.Equal(t, request, opened, "length %d", length)

					response := openChunk(t, server, true, body)
					secured, err = server.secureAsymmetric(response)
					require.NoError(t, err)
					opened, err = client.openAsymmetric(secured)
					require.NoError(t, err, "length %d", length)
					assert.Equal(t, response, opened, "length %d", length)
				}
			})
		}
	}
}

func TestAsymmetricRejectsTampering(t *testing.T) {
	client, server := channelPair(t, "Basic256Sha256", readWriteModel.MessageSecurityMode_messageSecurityModeSignAndEncrypt, 2048, 2048)
	secured, err := client.secureAsymmetric(openChunk(t, client, false, []byte("open")))
	require.NoError(t, err)

	tampered := append([]byte(nil), secured...)
	tampered[len(tampered)-1] ^= 1
	_, err = server.openAsymmetric(tampered)
	assert.Error(t, err, "changed cipher text")

	// A chunk for someone else: the server checks the thumbprint names its certificate.
	other := identityForTest(t, "other", 2048)
	stranger, err := newChannelSecurity(client.policy, client.mode, client.localKey, client.localCertificate, other.certificate)
	require.NoError(t, err)
	misaddressed, err := stranger.secureAsymmetric(openChunk(t, stranger, false, []byte("open")))
	require.NoError(t, err)
	_, err = server.openAsymmetric(misaddressed)
	assert.ErrorContains(t, err, "not meant for")
}

func TestAsymmetricChecksTheSender(t *testing.T) {
	client, _ := channelPair(t, "Basic256Sha256", readWriteModel.MessageSecurityMode_messageSecurityModeSignAndEncrypt, 2048, 2048)
	// A server with another certificate answers the client.
	impostor := identityForTest(t, "impostor", 2048)
	fake, err := newChannelSecurity(client.policy, client.mode, impostor.key, impostor.certificate.Raw, identityForTest(t, "client", 2048).certificate)
	require.NoError(t, err)
	secured, err := fake.secureAsymmetric(openChunk(t, fake, true, []byte("open")))
	require.NoError(t, err)
	_, err = client.openAsymmetric(secured)
	assert.ErrorContains(t, err, "another certificate")
}

func installTokens(t *testing.T, client, server *channelSecurity, tokenId uint32) {
	clientNonce, err := client.newLocalNonce()
	require.NoError(t, err)
	serverNonce, err := server.newLocalNonce()
	require.NoError(t, err)
	require.NoError(t, client.installToken(tokenId, serverNonce))
	require.NoError(t, server.installToken(tokenId, clientNonce))
}

func TestSymmetricRoundTrip(t *testing.T) {
	for _, policy := range securityPolicies[1:] {
		for _, mode := range testModes {
			t.Run(policy.name+"/"+mode.name, func(t *testing.T) {
				client, server := channelPair(t, policy.name, mode.mode, 2048, 2048)
				installTokens(t, client, server, 5)
				for _, length := range []int{0, 1, 15, 16, 17, 1000} {
					body := make([]byte, length)
					_, _ = rand.Read(body)
					chunk := messageChunk(t, body)
					secured, err := client.secureSymmetric(chunk)
					require.NoError(t, err)
					assert.Equal(t, uint32(len(secured)), binary.LittleEndian.Uint32(secured[4:8]), "size field")
					assert.Equal(t, uint32(5), binary.LittleEndian.Uint32(secured[12:16]), "token id")
					if mode.mode == readWriteModel.MessageSecurityMode_messageSecurityModeSignAndEncrypt {
						assert.Zero(t, (len(secured)-symmetricSecurityHeaderEnd)%16, "whole blocks")
					}
					opened, err := server.openSymmetric(secured)
					require.NoError(t, err, "length %d", length)
					expected := append([]byte(nil), chunk...)
					binary.LittleEndian.PutUint32(expected[12:16], 5)
					assert.Equal(t, expected, opened, "length %d", length)

					tampered := append([]byte(nil), secured...)
					tampered[len(tampered)/2] ^= 1
					_, err = server.openSymmetric(tampered)
					assert.Error(t, err, "tampered, length %d", length)
				}
			})
		}
	}
}

func TestSymmetricKeepsThePreviousToken(t *testing.T) {
	client, server := channelPair(t, "Basic256Sha256", readWriteModel.MessageSecurityMode_messageSecurityModeSignAndEncrypt, 2048, 2048)
	installTokens(t, client, server, 1)
	early, err := server.secureSymmetric(messageChunk(t, []byte("sent with token 1")))
	require.NoError(t, err)

	installTokens(t, client, server, 2)
	late, err := server.secureSymmetric(messageChunk(t, []byte("sent with token 2")))
	require.NoError(t, err)

	_, err = client.openSymmetric(early)
	assert.NoError(t, err, "a chunk of the previous token")
	_, err = client.openSymmetric(late)
	assert.NoError(t, err)

	installTokens(t, client, server, 3)
	_, err = client.openSymmetric(early)
	assert.ErrorContains(t, err, "unknown security token 1")
}

func TestMaxSymmetricBodySize(t *testing.T) {
	for _, policy := range securityPolicies {
		modes := testModes
		if policy.isNone() {
			modes = testModes[:1]
		}
		for _, mode := range modes {
			t.Run(policy.name+"/"+mode.name, func(t *testing.T) {
				client, server := channelPair(t, policy.name, mode.mode, 2048, 2048)
				installTokens(t, client, server, 1)
				for _, chunkSize := range []int{256, 8192, 65535} {
					maxBody := client.maxSymmetricBodySize(chunkSize)
					secured, err := client.secureSymmetric(messageChunk(t, make([]byte, maxBody)))
					require.NoError(t, err)
					assert.LessOrEqual(t, len(secured), chunkSize, "largest body fits")
					secured, err = client.secureSymmetric(messageChunk(t, make([]byte, maxBody+16)))
					require.NoError(t, err)
					assert.Greater(t, len(secured), chunkSize, "a block more does not")
				}
			})
		}
	}
}

func TestSessionSignature(t *testing.T) {
	for _, policy := range securityPolicies[1:] {
		t.Run(policy.name, func(t *testing.T) {
			client, server := channelPair(t, policy.name, readWriteModel.MessageSecurityMode_messageSecurityModeSign, 2048, 2048)
			clientNonce := []byte("client session nonce")
			// The server signs the client certificate and nonce; the client checks it.
			algorithm, signature, err := server.signSession(clientNonce)
			require.NoError(t, err)
			require.NoError(t, client.verifySession(clientNonce, algorithm, signature))
			assert.Error(t, client.verifySession([]byte("another nonce"), algorithm, signature))
		})
	}
}

func TestNoneSecurityPassesChunksThrough(t *testing.T) {
	policy, err := securityPolicyByName("None")
	require.NoError(t, err)
	none, err := newChannelSecurity(policy, readWriteModel.MessageSecurityMode_messageSecurityModeSignAndEncrypt, nil, nil, nil)
	require.NoError(t, err)
	assert.False(t, none.secured())
	chunk := messageChunk(t, []byte("plain"))
	secured, err := none.secureSymmetric(chunk)
	require.NoError(t, err)
	assert.Equal(t, chunk, secured)
	open := openChunk(t, none, false, []byte("plain"))
	secured, err = none.secureAsymmetric(open)
	require.NoError(t, err)
	assert.Equal(t, open, secured)
	opened, err := none.openAsymmetric(open)
	require.NoError(t, err)
	assert.Equal(t, open, opened)
}
