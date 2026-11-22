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
	"encoding/binary"

	readWriteModel "github.com/apache/plc4x/plc4go/protocols/opcua/readwrite/model"
	"github.com/apache/plc4x/plc4go/spi/errors"
)

// Sizes of the parts of a MSG chunk that are not the message body (OPC UA Part 6, 6.7.2).
const (
	// SECURE_MESSAGE_HEADER_SIZE covers the message type, the chunk type, the message size
	// and the secure channel id.
	SECURE_MESSAGE_HEADER_SIZE = 12
	// SYMMETRIC_SECURITY_HEADER_SIZE is the token id.
	SYMMETRIC_SECURITY_HEADER_SIZE = 4
	// SEQUENCE_HEADER_SIZE covers the sequence number and the request id.
	SEQUENCE_HEADER_SIZE = 8
	// CHUNK_OVERHEAD is what a chunk without signature or encryption adds to its body.
	CHUNK_OVERHEAD = SECURE_MESSAGE_HEADER_SIZE + SYMMETRIC_SECURITY_HEADER_SIZE + SEQUENCE_HEADER_SIZE
)

// applyServerLimits records the limits the server sent in its Acknowledge. The server's
// receive buffer bounds the chunks the driver sends; the driver's own send buffer
// (DEFAULT_SEND_BUFFER_SIZE) bounds them too. A max message size or max chunk count of 0
// means the server sets no limit.
func (s *SecureChannel) applyServerLimits(limits readWriteModel.OpcuaProtocolLimits) {
	if limits == nil {
		return
	}
	sendBufferSize := DEFAULT_SEND_BUFFER_SIZE
	if receiveBufferSize := limits.GetReceiveBufferSize(); receiveBufferSize > 0 && receiveBufferSize < sendBufferSize {
		sendBufferSize = receiveBufferSize
	}
	s.sendBufferSize = int(sendBufferSize)
	s.maxMessageSize = int(limits.GetMaxMessageSize())
	s.maxChunkCount = int(limits.GetMaxChunkCount())
	s.log.Debug().
		Int("sendBufferSize", s.sendBufferSize).
		Int("maxMessageSize", s.maxMessageSize).
		Int("maxChunkCount", s.maxChunkCount).
		Msg("server limits")
}

// splitBody cuts a message body into the bodies of the chunks that carry it, each small
// enough for the server's receive buffer. It refuses a message larger than the server's max
// message size or one that needs more chunks than the server's max chunk count. A message
// always has at least one chunk, even when its body is empty.
func (s *SecureChannel) splitBody(body []byte) ([][]byte, error) {
	if s.maxMessageSize > 0 && len(body) > s.maxMessageSize {
		return nil, errors.Errorf("message of %d bytes exceeds the server's max message size of %d bytes", len(body), s.maxMessageSize)
	}
	sendBufferSize := s.sendBufferSize
	if sendBufferSize <= 0 {
		sendBufferSize = int(DEFAULT_SEND_BUFFER_SIZE)
	}
	maxBodySize := sendBufferSize - CHUNK_OVERHEAD
	if s.security != nil {
		maxBodySize = s.security.maxSymmetricBodySize(sendBufferSize)
	}
	if maxBodySize <= 0 {
		return nil, errors.Errorf("send buffer size %d leaves no room for a message body", sendBufferSize)
	}
	chunks := make([][]byte, 0, len(body)/maxBodySize+1)
	for start := 0; start < len(body) || len(chunks) == 0; start += maxBodySize {
		end := min(start+maxBodySize, len(body))
		chunks = append(chunks, body[start:end])
	}
	if s.maxChunkCount > 0 && len(chunks) > s.maxChunkCount {
		return nil, errors.Errorf("message of %d bytes needs %d chunks, more than the server's max chunk count of %d", len(body), len(chunks), s.maxChunkCount)
	}
	return chunks, nil
}

// chunkAssembler joins the bodies of a response's chunks into the response. It holds the
// limits the driver advertised in its Hello: DEFAULT_MAX_CHUNK_COUNT chunks and
// DEFAULT_MAX_MESSAGE_SIZE bytes.
type chunkAssembler struct {
	parts [][]byte
	size  int
}

// add appends the body of the next chunk, refusing one that breaks the driver's limits.
func (a *chunkAssembler) add(body []byte) error {
	if len(a.parts)+1 > DEFAULT_MAX_CHUNK_COUNT {
		return errors.Errorf("response has more than %d chunks", DEFAULT_MAX_CHUNK_COUNT)
	}
	if uint64(a.size)+uint64(len(body)) > uint64(DEFAULT_MAX_MESSAGE_SIZE) {
		return errors.Errorf("response is larger than %d bytes", DEFAULT_MAX_MESSAGE_SIZE)
	}
	a.parts = append(a.parts, body)
	a.size += len(body)
	return nil
}

// message returns the bodies added so far, joined.
func (a *chunkAssembler) message() []byte {
	if len(a.parts) == 1 {
		return a.parts[0]
	}
	message := make([]byte, 0, a.size)
	for _, part := range a.parts {
		message = append(message, part...)
	}
	return message
}

// abortError turns the body of an abort chunk (a status code and a reason) into an error.
func abortError(body []byte) error {
	if len(body) < 4 {
		return errors.New("server aborted the message")
	}
	statusCode := binary.LittleEndian.Uint32(body[0:4])
	reason := ""
	if len(body) >= 8 {
		if length := int32(binary.LittleEndian.Uint32(body[4:8])); length > 0 && int(length) <= len(body)-8 {
			reason = string(body[8 : 8+int(length)])
		}
	}
	if reason == "" {
		return errors.Errorf("server aborted the message: status 0x%08X", statusCode)
	}
	return errors.Errorf("server aborted the message: status 0x%08X: %s", statusCode, reason)
}
