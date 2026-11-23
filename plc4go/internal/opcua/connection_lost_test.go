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
	"encoding/binary"
	"io"
	"net"
	"net/url"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	readWriteModel "github.com/apache/plc4x/plc4go/protocols/opcua/readwrite/model"
	"github.com/apache/plc4x/plc4go/spi/testutils"
	"github.com/apache/plc4x/plc4go/spi/transports/tcp"
	"github.com/apache/plc4x/plc4go/spi/transports/test"
	"github.com/apache/plc4x/plc4go/spi/utils"
)

// failFast is how soon a request has to end once the server has failed the connection: well
// short of the 20 seconds that the requests' contexts allow.
const failFast = 5 * time.Second

func errorChunk(t *testing.T, status readWriteModel.OpcuaStatusCode, reason string) []byte {
	chunk, err := readWriteModel.NewOpcuaAPU(readWriteModel.NewOpcuaMessageError(
		readWriteModel.ChunkType_FINAL, status, stringOf(reason))).Serialize()
	require.NoError(t, err)
	return chunk
}

// A server that refuses CreateSession with an Error message, as the OPC UA Local Discovery
// Server does, fails the connection setup at once and with the server's status.
func TestHandshakeReportsAnErrorMessage(t *testing.T) {
	serverIdentity := identityForTest(t, "server", 2048)
	for _, policy := range []string{"None", "Basic256Sha256"} {
		t.Run(policy, func(t *testing.T) {
			configuration := createDefaultConfiguration()
			configuration.SecurityPolicy = policy
			rig := newHandshakeRig(t, configuration, serverIdentity, serverIdentity.certificate)
			// CreateSession is the first service request.
			rig.server.refusal = errorChunk(t, readWriteModel.OpcuaStatusCode_BadServiceUnsupported, "no sessions here")

			began := time.Now()
			err := rig.connect(t)
			assert.Less(t, time.Since(began), failFast)
			require.ErrorContains(t, err, "BadServiceUnsupported")
			assert.ErrorContains(t, err, "0x800B0000")
			assert.ErrorContains(t, err, "no sessions here")
		})
	}
}

// An Error message while a request is still being written reports once: the exchange does not
// block on its own second error, the failed write.
func TestExchangeSurvivesAnErrorMessageDuringTheWrite(t *testing.T) {
	rig := newChunkTestRig(t, int(DEFAULT_SEND_BUFFER_SIZE))
	refusal := errorChunk(t, readWriteModel.OpcuaStatusCode_BadTcpEndpointUrlInvalid, "")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	rig.transport.SetWriteInterceptor(func(transport *test.TransportInstance, _ []byte) {
		transport.FillReadBuffer(refusal)
		time.Sleep(500 * time.Millisecond) // the expectation's error handler has run
		cancel()                           // and now the write fails as well
	})

	done := make(chan error, 1)
	go func() { done <- rig.channel.hello(ctx, rig.codec) }()
	select {
	case err := <-done:
		// Either of the two errors may be the one returned; what matters is that one is.
		assert.Error(t, err)
	case <-time.After(failFast):
		t.Fatal("exchange is blocked")
	}
}

// tcpRig is a channel on a real TCP connection: EOF and resets do not exist on the in-memory
// transport.
type tcpRig struct {
	channel *SecureChannel
	codec   *MessageCodec
	server  *net.TCPConn
}

func newTCPRig(t *testing.T) *tcpRig {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	_options := testutils.EnrichOptionsWithOptionsForTesting(t)
	instance, err := tcp.NewTransport(_options...).CreateTransportInstance(
		url.URL{Scheme: "tcp", Host: listener.Addr().String()}, map[string][]string{}, _options...)
	require.NoError(t, err)
	codec := NewMessageCodec(instance, _options...)
	require.NoError(t, codec.Connect(testutils.TestContext(t)))
	t.Cleanup(func() { _ = codec.Disconnect() })

	server, err := listener.Accept()
	require.NoError(t, err)
	t.Cleanup(func() { _ = server.Close() })
	require.NoError(t, server.SetDeadline(time.Now().Add(20*time.Second)))

	channel := NewSecureChannel(zerolog.Nop(), DriverContext{}, createDefaultConfiguration())
	channel.channelId.Store(7)
	channel.tokenId.Store(1)
	return &tcpRig{channel: channel, codec: codec, server: server.(*net.TCPConn)}
}

// readRequest reads one chunk of the client's.
func (r *tcpRig) readRequest(t *testing.T) {
	header := make([]byte, 8)
	_, err := io.ReadFull(r.server, header)
	require.NoError(t, err)
	_, err = io.CopyN(io.Discard, r.server, int64(binary.LittleEndian.Uint32(header[4:]))-8)
	require.NoError(t, err)
}

type submitResult struct {
	response []byte
	err      error
}

// submit sends a request and returns once the server has read it.
func (r *tcpRig) submit(t *testing.T) <-chan submitResult {
	results := make(chan submitResult, 4)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)
	buffer := utils.NewWriteBufferByteBased(utils.WithByteOrderForByteBasedBuffer(binary.LittleEndian))
	require.NoError(t, buffer.WriteByteArray("body", []byte("request")))
	r.channel.submit(ctx, r.codec,
		func(err error) { results <- submitResult{err: err} },
		func(response []byte) { results <- submitResult{response: response} },
		buffer)
	r.readRequest(t)
	return results
}

// However the server ends the connection, every waiting request fails and the codec stops.
func TestLostConnectionFailsTheWaitingRequests(t *testing.T) {
	sendError := func(t *testing.T, server *net.TCPConn) {
		_, err := server.Write(errorChunk(t, readWriteModel.OpcuaStatusCode_BadServiceUnsupported, ""))
		require.NoError(t, err)
	}
	tests := []struct {
		name string
		end  func(t *testing.T, server *net.TCPConn)
		want string
	}{
		{name: "error message, then close", want: "BadServiceUnsupported", end: func(t *testing.T, server *net.TCPConn) {
			sendError(t, server)
			require.NoError(t, server.Close())
		}},
		{name: "error message, socket left open", want: "BadServiceUnsupported", end: sendError},
		{name: "close", want: "EOF", end: func(t *testing.T, server *net.TCPConn) {
			require.NoError(t, server.Close())
		}},
		{name: "close inside a header", want: "connection lost", end: func(t *testing.T, server *net.TCPConn) {
			_, err := server.Write([]byte("MSGF"))
			require.NoError(t, err)
			require.NoError(t, server.Close())
		}},
		{name: "reset", want: "connection lost", end: func(t *testing.T, server *net.TCPConn) {
			require.NoError(t, server.SetLinger(0))
			require.NoError(t, server.Close())
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rig := newTCPRig(t)
			waiting := []<-chan submitResult{rig.submit(t), rig.submit(t)}
			tt.end(t, rig.server)

			deadline := time.After(failFast)
			for i, results := range waiting {
				select {
				case result := <-results:
					assert.ErrorContains(t, result.err, tt.want, "request %d", i)
				case <-deadline:
					t.Fatalf("request %d still waits", i)
				}
			}
			assert.Eventually(t, func() bool { return !rig.codec.IsRunning() }, failFast, 10*time.Millisecond)
		})
	}
}

// A server that is only slow has not lost the connection: the transport's read poll times out
// each second while the request waits, also in the middle of a header.
func TestSlowServerKeepsTheConnection(t *testing.T) {
	for _, split := range []int{0, 4} {
		rig := newTCPRig(t)
		results := rig.submit(t)
		response, err := readWriteModel.NewOpcuaAPU(readWriteModel.NewOpcuaMessageResponse(
			readWriteModel.ChunkType_FINAL,
			readWriteModel.NewSecurityHeader(7, 1),
			readWriteModel.NewBinaryPayload(readWriteModel.NewSequenceHeader(1, 0), []byte("answer")),
		)).Serialize()
		require.NoError(t, err)
		_, err = rig.server.Write(response[:split])
		require.NoError(t, err)
		time.Sleep(2500 * time.Millisecond)
		_, err = rig.server.Write(response[split:])
		require.NoError(t, err)

		select {
		case result := <-results:
			require.NoError(t, result.err)
			assert.Equal(t, []byte("answer"), result.response)
		case <-time.After(failFast):
			t.Fatal("no response")
		}
		assert.True(t, rig.codec.IsRunning())
	}
}

// A lost connection no longer reports as connected, so a connection cache replaces it.
func TestLostConnectionIsInvalidated(t *testing.T) {
	rig := newTCPRig(t)
	configuration := createDefaultConfiguration()
	connection := NewConnection(rig.codec, configuration, NewDriverContext(configuration), NewTagHandler(), nil,
		testutils.EnrichOptionsWithOptionsForTesting(t)...)
	connection.SetConnected(true)
	rig.submit(t)
	require.NoError(t, rig.server.Close())
	assert.Eventually(t, func() bool { return !connection.IsConnected() }, failFast, 10*time.Millisecond)
}

// Publish loops end with their connection: requests fail at once on a lost one, and the loops
// would retry on it for as long as the process runs.
func TestPublishLoopEndsWithTheConnection(t *testing.T) {
	rig := newTCPRig(t)
	ctx, cancel := context.WithCancel(context.Background())
	handle := &SubscriptionHandle{
		connection:       &Connection{messageCodec: rig.codec, channel: rig.channel},
		subscriptionId:   1,
		revisedCycleTime: 50 * time.Millisecond,
		keepAliveCount:   100,
		ctx:              ctx,
		cancel:           cancel,
		log:              zerolog.Nop(),
	}
	handle.plcSubscriber = &Subscriber{subscriptions: map[uint32]*SubscriptionHandle{1: handle}}

	done := make(chan struct{})
	go func() {
		defer close(done)
		handle.publishLoop()
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	rig.readRequest(t) // the Publish request is on its way
	require.NoError(t, rig.server.Close())

	select {
	case <-done:
		assert.Empty(t, handle.plcSubscriber.subscriptions)
	case <-time.After(failFast):
		t.Fatal("the Publish loop goes on without a connection")
	}
}
