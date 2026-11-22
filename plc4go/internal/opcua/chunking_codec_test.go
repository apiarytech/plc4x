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
	"net/url"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	readWriteModel "github.com/apache/plc4x/plc4go/protocols/opcua/readwrite/model"
	"github.com/apache/plc4x/plc4go/spi/testutils"
	"github.com/apache/plc4x/plc4go/spi/transports/test"
	"github.com/apache/plc4x/plc4go/spi/utils"
)

// chunkTestRig is a SecureChannel without security on a codec over the in-memory transport.
type chunkTestRig struct {
	channel   *SecureChannel
	codec     *MessageCodec
	transport *test.TransportInstance
	responses chan []byte
	errs      chan error
}

func newChunkTestRig(t *testing.T, sendBufferSize int) *chunkTestRig {
	_options := testutils.EnrichOptionsWithOptionsForTesting(t)
	transport := test.NewTransport(_options...)
	transportInstance, err := transport.CreateTransportInstance(url.URL{Scheme: "test"}, nil, _options...)
	require.NoError(t, err)
	testTransportInstance := transportInstance.(*test.TransportInstance)
	codec := NewMessageCodec(testTransportInstance, _options...)
	require.NoError(t, codec.Connect(testutils.TestContext(t)))
	t.Cleanup(func() { _ = codec.Disconnect() })

	log := zerolog.Nop()
	channel := &SecureChannel{
		log:                       log,
		channelTransactionManager: NewSecureChannelTransactionManager(log),
		encryptionHandler:         NewEncryptionHandler(log, nil, nil, "None"),
		sendBufferSize:            sendBufferSize,
	}
	channel.channelId.Store(7)
	channel.tokenId.Store(1)
	return &chunkTestRig{
		channel:   channel,
		codec:     codec,
		transport: testTransportInstance,
		responses: make(chan []byte, 1),
		errs:      make(chan error, 4),
	}
}

func (r *chunkTestRig) submit(t *testing.T, body []byte) {
	buffer := utils.NewWriteBufferByteBased(utils.WithByteOrderForByteBasedBuffer(binary.LittleEndian))
	require.NoError(t, buffer.WriteByteArray("body", body))
	r.channel.submit(testutils.TestContext(t), r.codec,
		func(err error) { r.errs <- err },
		func(response []byte) { r.responses <- response },
		buffer)
}

// sentChunks parses the chunks the channel wrote, waiting for count of them.
func (r *chunkTestRig) sentChunks(t *testing.T, count int) []readWriteModel.OpcuaMessageRequest {
	var chunks []readWriteModel.OpcuaMessageRequest
	var written []byte
	deadline := time.Now().Add(5 * time.Second)
	for len(chunks) < count {
		require.True(t, time.Now().Before(deadline), "got %d of %d chunks", len(chunks), count)
		written = append(written, r.transport.DrainWriteBuffer(r.transport.GetNumDrainableBytes())...)
		for len(written) >= 8 {
			size := int(binary.LittleEndian.Uint32(written[4:8]))
			if len(written) < size {
				break
			}
			apu, err := readWriteModel.OpcuaAPUParse(context.Background(), written[:size], false, true)
			require.NoError(t, err)
			chunks = append(chunks, apu.GetMessage().(readWriteModel.OpcuaMessageRequest))
			written = written[size:]
		}
		time.Sleep(5 * time.Millisecond)
	}
	return chunks
}

// respond feeds the channel a response chunk for requestId.
func (r *chunkTestRig) respond(t *testing.T, chunkType readWriteModel.ChunkType, sequenceNumber, requestId int32, body []byte) {
	apu := readWriteModel.NewOpcuaAPU(readWriteModel.NewOpcuaMessageResponse(
		chunkType,
		readWriteModel.NewSecurityHeader(7, 1),
		readWriteModel.NewBinaryPayload(readWriteModel.NewSequenceHeader(sequenceNumber, requestId), body),
	))
	bytes, err := apu.Serialize()
	require.NoError(t, err)
	r.transport.FillReadBuffer(bytes)
}

func pattern(size int) []byte {
	body := make([]byte, size)
	for i := range body {
		body[i] = byte(i % 251)
	}
	return body
}

func TestSubmitSplitsALargeRequest(t *testing.T) {
	rig := newChunkTestRig(t, CHUNK_OVERHEAD+40)
	body := pattern(100)
	rig.submit(t, body)

	chunks := rig.sentChunks(t, 3)
	var joined []byte
	for i, chunk := range chunks {
		want := readWriteModel.ChunkType_CONTINUE
		if i == 2 {
			want = readWriteModel.ChunkType_FINAL
		}
		assert.Equal(t, want, chunk.GetChunk(), "chunk %d", i)
		payload := chunk.GetMessage().(readWriteModel.BinaryPayload)
		assert.Equal(t, int32(i), payload.GetSequenceHeader().GetSequenceNumber(), "sequence number of chunk %d", i)
		assert.Equal(t, int32(0), payload.GetSequenceHeader().GetRequestId(), "request id of chunk %d", i)
		assert.Equal(t, uint32(7), chunk.GetSecurityHeader().GetSecureChannelId())
		joined = append(joined, payload.GetPayload()...)
	}
	assert.Equal(t, body, joined)

	// The next message continues after the three sequence numbers the chunks used.
	assert.Equal(t, int32(3), rig.channel.channelTransactionManager.getTransactionIdentifier())
}

func TestSubmitJoinsAChunkedResponse(t *testing.T) {
	rig := newChunkTestRig(t, int(DEFAULT_SEND_BUFFER_SIZE))
	rig.submit(t, []byte("read request"))
	rig.sentChunks(t, 1)

	response := pattern(300)
	rig.respond(t, readWriteModel.ChunkType_CONTINUE, 1, 0, response[:100])
	rig.respond(t, readWriteModel.ChunkType_CONTINUE, 2, 0, response[100:200])
	rig.respond(t, readWriteModel.ChunkType_FINAL, 3, 0, response[200:])

	select {
	case got := <-rig.responses:
		assert.Equal(t, response, got)
	case err := <-rig.errs:
		t.Fatalf("unexpected error: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("no response")
	}
}

func TestSubmitReportsAnAbortedResponse(t *testing.T) {
	rig := newChunkTestRig(t, int(DEFAULT_SEND_BUFFER_SIZE))
	rig.submit(t, []byte("read request"))
	rig.sentChunks(t, 1)

	abort := binary.LittleEndian.AppendUint32(nil, 0x80AC0000)
	abort = binary.LittleEndian.AppendUint32(abort, 4)
	abort = append(abort, "full"...)
	rig.respond(t, readWriteModel.ChunkType_CONTINUE, 1, 0, pattern(10))
	rig.respond(t, readWriteModel.ChunkType_ABORT, 2, 0, abort)

	select {
	case got := <-rig.responses:
		t.Fatalf("unexpected response of %d bytes", len(got))
	case err := <-rig.errs:
		assert.EqualError(t, err, "server aborted the message: status 0x80AC0000: full")
	case <-time.After(5 * time.Second):
		t.Fatal("no error")
	}
}

func TestSubmitRefusesARequestTheServerCannotTake(t *testing.T) {
	rig := newChunkTestRig(t, CHUNK_OVERHEAD+10)
	rig.channel.maxChunkCount = 2
	rig.submit(t, pattern(21))

	select {
	case err := <-rig.errs:
		assert.ErrorContains(t, err, "max chunk count")
	case <-time.After(5 * time.Second):
		t.Fatal("no error")
	}
	assert.Zero(t, rig.transport.GetNumDrainableBytes(), "nothing is sent")
}
