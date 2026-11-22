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
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/binary"
	"sync"

	readWriteModel "github.com/apache/plc4x/plc4go/protocols/opcua/readwrite/model"
	"github.com/apache/plc4x/plc4go/spi/errors"
)

// channelSecurity signs, encrypts, verifies and decrypts the chunks of one secure channel
// (OPC UA Part 6, 6.7). It works on whole serialized chunks: OpenSecureChannel chunks with the
// asymmetric algorithms of the policy, every other chunk with the symmetric keys derived from
// both sides' nonces.
//
// "Local" is the side that holds this value, "remote" its peer: the driver is the local side
// of its channels, and a test can build the server's side the same way.
type channelSecurity struct {
	policy *securityPolicy
	mode   readWriteModel.MessageSecurityMode

	localKey          *rsa.PrivateKey
	localCertificate  []byte // DER
	remoteCertificate *x509.Certificate

	mutex sync.RWMutex
	// localNonce is the nonce of the OpenSecureChannel request in flight; tokens holds the
	// keys of the current token and of the one before it, which the remote side may still
	// use for a while after a renewal.
	localNonce   []byte
	currentToken uint32
	tokens       map[uint32]tokenKeys
}

// tokenKeys are the keys of one security token: the local side secures with local and
// checks what it receives with remote.
type tokenKeys struct {
	local, remote keySet
}

// newChannelSecurity builds the security of a channel. For a policy other than None and a mode
// other than None it needs the local key and certificate and the remote certificate.
func newChannelSecurity(policy *securityPolicy, mode readWriteModel.MessageSecurityMode, localKey *rsa.PrivateKey, localCertificate []byte, remoteCertificate *x509.Certificate) (*channelSecurity, error) {
	c := &channelSecurity{
		policy:            policy,
		mode:              mode,
		localKey:          localKey,
		localCertificate:  localCertificate,
		remoteCertificate: remoteCertificate,
		tokens:            map[uint32]tokenKeys{},
	}
	if policy.isNone() {
		c.mode = readWriteModel.MessageSecurityMode_messageSecurityModeNone
		return c, nil
	}
	if c.mode == readWriteModel.MessageSecurityMode_messageSecurityModeNone {
		return nil, errors.Errorf("security policy %s needs message security Sign or SignAndEncrypt", policy.name)
	}
	if localKey == nil || len(localCertificate) == 0 {
		return nil, errors.Errorf("security policy %s needs a client certificate and key", policy.name)
	}
	if remoteCertificate == nil {
		return nil, errors.Errorf("security policy %s needs the server's certificate", policy.name)
	}
	if _, ok := remoteCertificate.PublicKey.(*rsa.PublicKey); !ok {
		return nil, errors.Errorf("server certificate has a %T key, the security policies need RSA", remoteCertificate.PublicKey)
	}
	return c, nil
}

// secured reports whether chunks are signed (and maybe encrypted).
func (c *channelSecurity) secured() bool {
	return c.mode != readWriteModel.MessageSecurityMode_messageSecurityModeNone
}

// encrypted reports whether symmetric chunks are encrypted as well as signed.
func (c *channelSecurity) encrypted() bool {
	return c.mode == readWriteModel.MessageSecurityMode_messageSecurityModeSignAndEncrypt
}

func (c *channelSecurity) remoteKey() *rsa.PublicKey {
	return c.remoteCertificate.PublicKey.(*rsa.PublicKey)
}

// localThumbprint is the SHA-1 thumbprint of the local certificate.
func (c *channelSecurity) localThumbprint() []byte {
	if len(c.localCertificate) == 0 {
		return nil
	}
	sum := sha1.Sum(c.localCertificate)
	return sum[:]
}

// remoteThumbprint is the SHA-1 thumbprint of the remote certificate, which an
// OpenSecureChannel request names as its receiver.
func (c *channelSecurity) remoteThumbprint() []byte {
	if c.remoteCertificate == nil {
		return nil
	}
	sum := sha1.Sum(c.remoteCertificate.Raw)
	return sum[:]
}

// localCertificateIfSecured is the local certificate an OpenSecureChannel or CreateSession
// request carries: none without security.
func (c *channelSecurity) localCertificateIfSecured() []byte {
	if !c.secured() {
		return nil
	}
	return c.localCertificate
}

// remoteThumbprintIfSecured is the thumbprint an OpenSecureChannel request names its receiver
// by: none without security.
func (c *channelSecurity) remoteThumbprintIfSecured() []byte {
	if !c.secured() {
		return nil
	}
	return c.remoteThumbprint()
}

// newLocalNonce makes the nonce of the next OpenSecureChannel request; nil without security.
func (c *channelSecurity) newLocalNonce() ([]byte, error) {
	if !c.secured() {
		return nil, nil
	}
	nonce := make([]byte, c.policy.nonceLength)
	if _, err := cryptoRandRead(nonce); err != nil {
		return nil, errors.Wrap(err, "error making nonce")
	}
	c.mutex.Lock()
	c.localNonce = nonce
	c.mutex.Unlock()
	return nonce, nil
}

// installToken derives the keys of a token from the nonce of the request that asked for it and
// the remote side's nonce, and makes it the current token. The token before it stays known,
// for chunks the remote side secured before it switched.
func (c *channelSecurity) installToken(tokenId uint32, remoteNonce []byte) error {
	if !c.secured() {
		return nil
	}
	c.mutex.Lock()
	defer c.mutex.Unlock()
	if len(remoteNonce) != c.policy.nonceLength {
		return errors.Errorf("server nonce has %d bytes, security policy %s needs %d", len(remoteNonce), c.policy.name, c.policy.nonceLength)
	}
	if len(c.localNonce) != c.policy.nonceLength {
		return errors.New("no client nonce for the token")
	}
	keys := tokenKeys{
		local:  c.policy.deriveKeys(remoteNonce, c.localNonce),
		remote: c.policy.deriveKeys(c.localNonce, remoteNonce),
	}
	for id := range c.tokens {
		if id != c.currentToken {
			delete(c.tokens, id)
		}
	}
	c.tokens[tokenId] = keys
	c.currentToken = tokenId
	return nil
}

// Layout of a chunk: the message header (type, chunk type, size, channel id), the security
// header, then the sequence header and body, which is what gets padded, signed and encrypted.
const symmetricSecurityHeaderEnd = SECURE_MESSAGE_HEADER_SIZE + SYMMETRIC_SECURITY_HEADER_SIZE

// asymmetricHeader is the security header of an OpenSecureChannel chunk.
type asymmetricHeader struct {
	policyUri          string
	senderCertificate  []byte
	receiverThumbprint []byte
	end                int // offset of the sequence header
}

func parseAsymmetricHeader(chunk []byte) (asymmetricHeader, error) {
	var header asymmetricHeader
	offset := SECURE_MESSAGE_HEADER_SIZE
	field := func() ([]byte, error) {
		if len(chunk) < offset+4 {
			return nil, errors.New("chunk too short for its security header")
		}
		length := int32(binary.LittleEndian.Uint32(chunk[offset:]))
		offset += 4
		if length < 0 {
			return nil, nil
		}
		if len(chunk) < offset+int(length) {
			return nil, errors.New("chunk too short for its security header")
		}
		value := chunk[offset : offset+int(length)]
		offset += int(length)
		return value, nil
	}
	policyUri, err := field()
	if err != nil {
		return header, err
	}
	if header.senderCertificate, err = field(); err != nil {
		return header, err
	}
	if header.receiverThumbprint, err = field(); err != nil {
		return header, err
	}
	header.policyUri = string(policyUri)
	header.end = offset
	return header, nil
}

func setChunkSize(chunk []byte) {
	binary.LittleEndian.PutUint32(chunk[4:8], uint32(len(chunk)))
}

// appendPadding pads chunk so its part from start on, the padding and a signature of
// signatureSize fill whole blocks of blockSize. The padding is a PaddingSize byte, that many bytes of the same value,
// and, when the encrypting key is larger than 2048 bits (extraPadding), an ExtraPaddingSize byte
// with the high byte of the size.
func appendPadding(chunk []byte, start, blockSize, signatureSize int, extraPadding bool) []byte {
	overhead := 1
	if extraPadding {
		overhead = 2
	}
	padding := (blockSize - (len(chunk)-start+overhead+signatureSize)%blockSize) % blockSize
	low := byte(padding)
	for range padding + 1 {
		chunk = append(chunk, low)
	}
	if extraPadding {
		chunk = append(chunk, byte(padding>>8))
	}
	return chunk
}

// removePadding checks and strips the padding at the end of plainText (signature already
// removed). start is where the sequence header begins.
func removePadding(plainText []byte, start int, extraPadding bool) ([]byte, error) {
	end := len(plainText)
	overhead := 1
	if extraPadding {
		overhead = 2
	}
	if end-start < SEQUENCE_HEADER_SIZE+overhead {
		return nil, errors.New("chunk too short for its padding")
	}
	low := plainText[end-overhead]
	padding := int(low)
	if extraPadding {
		padding |= int(plainText[end-1]) << 8
	}
	paddingStart := end - overhead - padding
	if paddingStart < start+SEQUENCE_HEADER_SIZE {
		return nil, errors.New("malformed padding")
	}
	for _, b := range plainText[paddingStart : end-overhead+1] {
		if b != low {
			return nil, errors.New("malformed padding")
		}
	}
	return plainText[:paddingStart], nil
}

// secureAsymmetric signs and encrypts a serialized OpenSecureChannel chunk with the local
// private key and the remote public key. Without security it returns the chunk as it is.
func (c *channelSecurity) secureAsymmetric(chunk []byte) ([]byte, error) {
	if !c.secured() {
		return chunk, nil
	}
	header, err := parseAsymmetricHeader(chunk)
	if err != nil {
		return nil, err
	}
	remoteKey := c.remoteKey()
	plainBlock := c.policy.asymmetricPlainTextBlockSize(remoteKey)
	signatureSize := c.localKey.Size()

	out := make([]byte, 0, len(chunk)+plainBlock+signatureSize)
	out = append(out, chunk...)
	out = appendPadding(out, header.end, plainBlock, signatureSize, remoteKey.Size() > 256)
	plainTextSize := len(out) - header.end + signatureSize
	binary.LittleEndian.PutUint32(out[4:8], uint32(header.end+plainTextSize/plainBlock*remoteKey.Size()))
	signature, err := c.policy.asymmetricSign(c.localKey, out)
	if err != nil {
		return nil, errors.Wrap(err, "error signing")
	}
	out = append(out, signature...)
	cipherText, err := c.policy.asymmetricEncryptAll(remoteKey, out[header.end:])
	if err != nil {
		return nil, err
	}
	return append(out[:header.end:header.end], cipherText...), nil
}

// openAsymmetric decrypts and verifies an OpenSecureChannel chunk from the remote side and
// returns it without padding and signature. It checks that the chunk uses the channel's
// policy, comes from the remote certificate and is meant for the local one.
func (c *channelSecurity) openAsymmetric(chunk []byte) ([]byte, error) {
	header, err := parseAsymmetricHeader(chunk)
	if err != nil {
		return nil, err
	}
	if header.policyUri != c.policy.uri {
		return nil, errors.Errorf("server answered with security policy %s, the channel uses %s", header.policyUri, c.policy.uri)
	}
	if !c.secured() {
		return chunk, nil
	}
	if !bytes.Equal(header.receiverThumbprint, c.localThumbprint()) {
		return nil, errors.New("server's OpenSecureChannel response is not meant for the client certificate")
	}
	senderCertificates, err := x509.ParseCertificates(header.senderCertificate)
	if err != nil || len(senderCertificates) == 0 {
		return nil, errors.Wrap(err, "error parsing the server's certificate")
	}
	if !bytes.Equal(senderCertificates[0].Raw, c.remoteCertificate.Raw) {
		return nil, errors.New("server signed its OpenSecureChannel response with another certificate than the one the channel was opened for")
	}
	blockSize := c.localKey.Size()
	cipherText := chunk[header.end:]
	if len(cipherText) == 0 || len(cipherText)%blockSize != 0 {
		return nil, errors.Errorf("encrypted part of %d bytes is not a whole number of %d byte blocks", len(cipherText), blockSize)
	}
	plain := make([]byte, header.end, header.end+len(cipherText))
	copy(plain, chunk[:header.end])
	for start := 0; start < len(cipherText); start += blockSize {
		block, err := c.policy.asymmetricDecrypt(c.localKey, cipherText[start:start+blockSize])
		if err != nil {
			return nil, errors.Wrap(err, "error decrypting")
		}
		plain = append(plain, block...)
	}
	signatureSize := c.remoteKey().Size()
	if len(plain)-header.end < signatureSize+SEQUENCE_HEADER_SIZE {
		return nil, errors.New("chunk too short for its signature")
	}
	signed, signature := plain[:len(plain)-signatureSize], plain[len(plain)-signatureSize:]
	if err := c.policy.asymmetricVerify(c.remoteKey(), signed, signature); err != nil {
		return nil, errors.Wrap(err, "server's OpenSecureChannel signature does not verify")
	}
	opened, err := removePadding(signed, header.end, c.localKey.Size() > 256)
	if err != nil {
		return nil, err
	}
	setChunkSize(opened)
	return opened, nil
}

// maxSymmetricBodySize is the largest message body a symmetric chunk of chunkSize bytes carries.
func (c *channelSecurity) maxSymmetricBodySize(chunkSize int) int {
	if !c.secured() {
		return chunkSize - CHUNK_OVERHEAD
	}
	signatureSize := c.policy.symmetricSignatureSize()
	if !c.encrypted() {
		return chunkSize - CHUNK_OVERHEAD - signatureSize
	}
	blockSize := c.policy.symmetricBlockSize()
	plainText := (chunkSize - symmetricSecurityHeaderEnd) / blockSize * blockSize
	return plainText - SEQUENCE_HEADER_SIZE - signatureSize - 1
}

// secureSymmetric signs, and with SignAndEncrypt pads and encrypts, a serialized MSG or CLO
// chunk with the current token's keys. Without security it returns the chunk as it is.
func (c *channelSecurity) secureSymmetric(chunk []byte) ([]byte, error) {
	if !c.secured() {
		return chunk, nil
	}
	c.mutex.RLock()
	keys, ok := c.tokens[c.currentToken]
	c.mutex.RUnlock()
	if !ok {
		return nil, errors.New("no security token yet")
	}
	if len(chunk) < symmetricSecurityHeaderEnd+SEQUENCE_HEADER_SIZE {
		return nil, errors.New("chunk too short")
	}
	signatureSize := c.policy.symmetricSignatureSize()
	out := make([]byte, 0, len(chunk)+c.policy.symmetricBlockSize()+signatureSize)
	out = append(out, chunk...)
	if c.encrypted() {
		out = appendPadding(out, symmetricSecurityHeaderEnd, c.policy.symmetricBlockSize(), signatureSize, false)
	}
	binary.LittleEndian.PutUint32(out[4:8], uint32(len(out)+signatureSize))
	binary.LittleEndian.PutUint32(out[SECURE_MESSAGE_HEADER_SIZE:], c.currentToken)
	out = append(out, c.policy.symmetricSign(keys.local, out)...)
	if c.encrypted() {
		if err := c.policy.symmetricCrypt(keys.local, out[symmetricSecurityHeaderEnd:], true); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// openSymmetric decrypts and verifies a MSG or CLO chunk from the remote side with the keys of
// the token it names, and returns it without padding and signature.
func (c *channelSecurity) openSymmetric(chunk []byte) ([]byte, error) {
	if !c.secured() {
		return chunk, nil
	}
	if len(chunk) < symmetricSecurityHeaderEnd+SEQUENCE_HEADER_SIZE {
		return nil, errors.New("chunk too short")
	}
	tokenId := binary.LittleEndian.Uint32(chunk[SECURE_MESSAGE_HEADER_SIZE:])
	c.mutex.RLock()
	keys, ok := c.tokens[tokenId]
	c.mutex.RUnlock()
	if !ok {
		return nil, errors.Errorf("chunk uses unknown security token %d", tokenId)
	}
	opened := bytes.Clone(chunk)
	if c.encrypted() {
		if err := c.policy.symmetricCrypt(keys.remote, opened[symmetricSecurityHeaderEnd:], false); err != nil {
			return nil, err
		}
	}
	signatureSize := c.policy.symmetricSignatureSize()
	if len(opened)-symmetricSecurityHeaderEnd < signatureSize+SEQUENCE_HEADER_SIZE {
		return nil, errors.New("chunk too short for its signature")
	}
	signed, signature := opened[:len(opened)-signatureSize], opened[len(opened)-signatureSize:]
	if err := c.policy.symmetricVerify(keys.remote, signed, signature); err != nil {
		return nil, err
	}
	if c.encrypted() {
		var err error
		if signed, err = removePadding(signed, symmetricSecurityHeaderEnd, false); err != nil {
			return nil, err
		}
	}
	setChunkSize(signed)
	return signed, nil
}

// signSession signs, for ActivateSession, the remote certificate followed by the remote
// side's session nonce (OPC UA Part 4, 5.6.3).
func (c *channelSecurity) signSession(remoteNonce []byte) (algorithm string, signature []byte, err error) {
	if !c.secured() {
		return "", nil, nil
	}
	data := append(bytes.Clone(c.remoteCertificate.Raw), remoteNonce...)
	signature, err = c.policy.asymmetricSign(c.localKey, data)
	if err != nil {
		return "", nil, errors.Wrap(err, "error signing")
	}
	return c.policy.asymmetricSignatureURI(), signature, nil
}

// verifySession checks the server's CreateSession signature over the local certificate
// followed by the local session nonce.
func (c *channelSecurity) verifySession(localNonce []byte, algorithm string, signature []byte) error {
	if !c.secured() {
		return nil
	}
	if algorithm != c.policy.asymmetricSignatureURI() {
		return errors.Errorf("server signed the session with %q, the security policy uses %q", algorithm, c.policy.asymmetricSignatureURI())
	}
	data := append(bytes.Clone(c.localCertificate), localNonce...)
	if err := c.policy.asymmetricVerify(c.remoteKey(), data, signature); err != nil {
		return errors.Wrap(err, "server's session signature does not verify")
	}
	return nil
}
