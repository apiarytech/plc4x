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
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	readWriteModel "github.com/apache/plc4x/plc4go/protocols/opcua/readwrite/model"
)

func TestApplyServerLimits(t *testing.T) {
	tests := []struct {
		name                                  string
		limits                                readWriteModel.OpcuaProtocolLimits
		sendBufferSize, maxMessage, maxChunks int
	}{
		{"server buffer smaller", readWriteModel.NewOpcuaProtocolLimits(8192, 8192, 1<<20, 16), 8192, 1 << 20, 16},
		{"server buffer larger", readWriteModel.NewOpcuaProtocolLimits(1<<20, 1<<20, 0, 0), int(DEFAULT_SEND_BUFFER_SIZE), 0, 0},
		{"server buffer unset", readWriteModel.NewOpcuaProtocolLimits(0, 0, 0, 0), int(DEFAULT_SEND_BUFFER_SIZE), 0, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &SecureChannel{log: zerolog.Nop()}
			s.applyServerLimits(tt.limits)
			assert.Equal(t, tt.sendBufferSize, s.sendBufferSize)
			assert.Equal(t, tt.maxMessage, s.maxMessageSize)
			assert.Equal(t, tt.maxChunks, s.maxChunkCount)
		})
	}
}

func TestSplitBody(t *testing.T) {
	body := make([]byte, 1000)
	for i := range body {
		body[i] = byte(i)
	}
	const sendBufferSize = 124 // 100 bytes of body per chunk
	tests := []struct {
		name       string
		size       int
		maxMessage int
		maxChunks  int
		chunkSizes []int
		wantErr    string
	}{
		{name: "empty", size: 0, chunkSizes: []int{0}},
		{name: "one chunk", size: 60, chunkSizes: []int{60}},
		{name: "exactly one chunk", size: 100, chunkSizes: []int{100}},
		{name: "two chunks", size: 101, chunkSizes: []int{100, 1}},
		{name: "many chunks", size: 1000, chunkSizes: []int{100, 100, 100, 100, 100, 100, 100, 100, 100, 100}},
		{name: "within chunk count", size: 300, maxChunks: 3, chunkSizes: []int{100, 100, 100}},
		{name: "over chunk count", size: 301, maxChunks: 3, wantErr: "max chunk count"},
		{name: "over message size", size: 501, maxMessage: 500, wantErr: "max message size"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &SecureChannel{sendBufferSize: sendBufferSize, maxMessageSize: tt.maxMessage, maxChunkCount: tt.maxChunks}
			chunks, err := s.splitBody(body[:tt.size])
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			sizes := make([]int, len(chunks))
			for i, chunk := range chunks {
				sizes[i] = len(chunk)
			}
			assert.Equal(t, tt.chunkSizes, sizes)
			assert.Equal(t, string(body[:tt.size]), string(bytes.Join(chunks, nil)))
		})
	}
}

func TestSplitBodyDefaultsToDriverBuffer(t *testing.T) {
	s := &SecureChannel{}
	chunks, err := s.splitBody(make([]byte, int(DEFAULT_SEND_BUFFER_SIZE)))
	require.NoError(t, err)
	require.Len(t, chunks, 2)
	assert.Len(t, chunks[0], int(DEFAULT_SEND_BUFFER_SIZE)-CHUNK_OVERHEAD)
}

func TestChunkAssembler(t *testing.T) {
	t.Run("joins chunks", func(t *testing.T) {
		var a chunkAssembler
		require.NoError(t, a.add([]byte("abc")))
		require.NoError(t, a.add([]byte("")))
		require.NoError(t, a.add([]byte("de")))
		assert.Equal(t, []byte("abcde"), a.message())
	})
	t.Run("single chunk", func(t *testing.T) {
		var a chunkAssembler
		require.NoError(t, a.add([]byte("abc")))
		assert.Equal(t, []byte("abc"), a.message())
	})
	t.Run("too many chunks", func(t *testing.T) {
		var a chunkAssembler
		for range DEFAULT_MAX_CHUNK_COUNT {
			require.NoError(t, a.add([]byte{1}))
		}
		assert.ErrorContains(t, a.add([]byte{1}), "more than")
	})
	t.Run("too large", func(t *testing.T) {
		var a chunkAssembler
		require.NoError(t, a.add(make([]byte, DEFAULT_MAX_MESSAGE_SIZE)))
		assert.ErrorContains(t, a.add([]byte{1}), "larger than")
	})
}

func TestAbortError(t *testing.T) {
	withReason := binary.LittleEndian.AppendUint32(nil, 0x80AC0000)
	withReason = binary.LittleEndian.AppendUint32(withReason, 7)
	withReason = append(withReason, "too big"...)
	nullReason := binary.LittleEndian.AppendUint32(nil, 0x80AC0000)
	nullReason = binary.LittleEndian.AppendUint32(nullReason, 0xFFFFFFFF)

	assert.EqualError(t, abortError(withReason), "server aborted the message: status 0x80AC0000: too big")
	assert.EqualError(t, abortError(nullReason), "server aborted the message: status 0x80AC0000")
	assert.EqualError(t, abortError(nil), "server aborted the message")
}

func TestTransactionManagerSpans(t *testing.T) {
	m := NewSecureChannelTransactionManager(zerolog.Nop())
	var sent []int32
	send := func(id int32) { sent = append(sent, id) }

	first := m.getTransactionIdentifiers(3) // a message in three chunks
	second := m.getTransactionIdentifier()
	third := m.getTransactionIdentifiers(2)
	assert.Equal(t, []int32{0, 3, 4}, []int32{first, second, third})

	// Submitted out of order: the later ones wait for the span before them.
	require.NoError(t, m.submitSpan(send, third, 2))
	require.NoError(t, m.submit(send, second))
	assert.Empty(t, sent)
	require.NoError(t, m.submitSpan(send, first, 3))
	assert.Equal(t, []int32{0, 3, 4}, sent)
	assert.Equal(t, int32(6), m.activeTransactionId.Load())
	assert.Equal(t, int32(6), m.getTransactionIdentifier())
}
