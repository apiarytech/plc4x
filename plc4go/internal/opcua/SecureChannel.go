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
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"regexp"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog"

	readWriteModel "github.com/apache/plc4x/plc4go/protocols/opcua/readwrite/model"
	"github.com/apache/plc4x/plc4go/spi"
	"github.com/apache/plc4x/plc4go/spi/errors"
	"github.com/apache/plc4x/plc4go/spi/utils"
)

const (
	VERSION                     = uint32(0)
	DEFAULT_MAX_CHUNK_COUNT     = 64
	DEFAULT_MAX_MESSAGE_SIZE    = uint32(2097152)
	DEFAULT_RECEIVE_BUFFER_SIZE = uint32(65535)
	DEFAULT_SEND_BUFFER_SIZE    = uint32(65535)
	REQUEST_TIMEOUT_LONG        = 10000
	EPOCH_OFFSET                = 116444736000000000 //Offset between OPC UA epoch time and linux epoch time.
	// SESSION_NONCE_LENGTH is the length of the client's CreateSession nonce.
	SESSION_NONCE_LENGTH = 32
	// SESSION_TIMEOUT is the session timeout the client asks for, in milliseconds.
	SESSION_TIMEOUT = 120000
	// HANDSHAKE_TIMEOUT bounds the whole connection setup.
	HANDSHAKE_TIMEOUT = 60 * time.Second
)

var (
	NULL_STRING          = readWriteModel.NewPascalString(nil)
	NULL_BYTE_STRING     = readWriteModel.NewPascalByteString(-1, nil)
	NULL_EXPANDED_NODEID = readWriteModel.NewExpandedNodeId(false,
		false,
		readWriteModel.NewNodeIdTwoByte(0),
		nil,
		nil,
	)
	BINARY_ENCODING_MASK  = readWriteModel.NewExtensionObjectEncodingMask(false, false, true)
	NULL_EXTENSION_OBJECT = readWriteModel.NewNullExtensionObjectWithMask(NULL_EXPANDED_NODEID,
		readWriteModel.NewExtensionObjectEncodingMask(false, false, false),
	) // Body

	INET_ADDRESS_PATTERN = regexp.MustCompile(`(.(?P<transportCode>tcp))?://(?P<transportHost>[\w.-]+)(:(?P<transportPort>\d*))?`)

	URI_PATTERN                 = regexp.MustCompile(`^(?P<protocolCode>opc)` + INET_ADDRESS_PATTERN.String() + `(?P<transportEndpoint>[\w/=]*)[?]?`)
	APPLICATION_URI             = readWriteModel.NewPascalString(new("urn:apache:plc4x:client"))
	PRODUCT_URI                 = readWriteModel.NewPascalString(new("urn:apache:plc4x:client"))
	APPLICATION_TEXT            = readWriteModel.NewPascalString(new("OPCUA client for the Apache PLC4X:PLC4J project"))
	DEFAULT_CONNECTION_LIFETIME = uint32(3600000)
)

// SecureChannel is the client's side of an OPC UA secure channel and the session on it: the
// handshake (Hello, OpenSecureChannel, CreateSession, ActivateSession), the renewal of the
// channel's security token, the requests of the readers, writers and subscribers, and the
// close.
//
//go:generate go tool plc4xGenerator -type=SecureChannel
type SecureChannel struct {
	sessionName            string
	requestHandleGenerator atomic.Uint32
	endpoint               readWriteModel.PascalString
	username               string
	password               string        `secret:"true"`
	configuration          Configuration `stringer:"true"`

	// security signs and encrypts the chunks; serverCertificate is the server's certificate as
	// discovered or pinned, nil without a security policy.
	security          *channelSecurity  `ignore:"true"`
	serverCertificate *x509.Certificate `ignore:"true"`

	channelId                 atomic.Uint32
	tokenId                   atomic.Uint32
	authenticationToken       readWriteModel.NodeIdTypeDefinition
	codec                     *MessageCodec
	channelTransactionManager *SecureChannelTransactionManager
	lifetime                  atomic.Uint32
	renewal                   chan struct{} `ignore:"true"` // closed to stop the token renewal
	renewalWg                 sync.WaitGroup
	sendBufferSize            int // largest chunk the server accepts, from its Acknowledge (see applyServerLimits)
	maxMessageSize            int // largest message the server accepts; 0: no limit
	maxChunkCount             int // most chunks per message the server accepts; 0: no limit
	senderSequenceNumber      atomic.Int32

	log zerolog.Logger
}

func NewSecureChannel(log zerolog.Logger, _ DriverContext, configuration Configuration) *SecureChannel {
	s := &SecureChannel{
		configuration:             configuration,
		endpoint:                  readWriteModel.NewPascalString(&configuration.Endpoint),
		username:                  configuration.Username,
		password:                  configuration.Password,
		sessionName:               "UaSession:" + *APPLICATION_TEXT.GetStringValue() + ":" + utils.RandomString(20),
		authenticationToken:       readWriteModel.NewNodeIdTwoByte(0),
		channelTransactionManager: NewSecureChannelTransactionManager(log),
		log:                       log,
	}
	s.lifetime.Store(DEFAULT_CONNECTION_LIFETIME)
	s.requestHandleGenerator.Store(1)
	none, _ := securityPolicyByName("None")
	s.security, _ = newChannelSecurity(none, readWriteModel.MessageSecurityMode_messageSecurityModeNone, nil, nil, nil)
	return s
}

// prepareSecurity sets up the channel's security policy for a server whose certificate is
// serverCertificate (nil for the None policy).
func (s *SecureChannel) prepareSecurity(identity clientIdentity, serverCertificate *x509.Certificate) error {
	policy, err := s.configuration.securityPolicy()
	if err != nil {
		return err
	}
	mode, err := s.configuration.messageSecurityMode()
	if err != nil {
		return err
	}
	security, err := newChannelSecurity(policy, mode, identity.key, identity.certificate, serverCertificate)
	if err != nil {
		return err
	}
	s.security = security
	s.serverCertificate = serverCertificate
	return nil
}

// encodeChunk serializes a chunk and, for MSG and CLO chunks, signs and encrypts it.
func (s *SecureChannel) encodeChunk(ctx context.Context, message readWriteModel.MessagePDU) (readWriteModel.OpcuaAPU, error) {
	apu := readWriteModel.NewOpcuaAPU(message)
	if !s.security.secured() {
		return apu, nil
	}
	plain, err := apu.Serialize()
	if err != nil {
		return nil, errors.Wrap(err, "error serializing")
	}
	if _, isOpen := message.(readWriteModel.OpcuaOpenRequest); isOpen {
		secured, err := s.security.secureAsymmetric(plain)
		if err != nil {
			return nil, err
		}
		return readWriteModel.OpcuaAPUParse(ctx, secured, false, true)
	}
	secured, err := s.security.secureSymmetric(plain)
	if err != nil {
		return nil, err
	}
	// The secured chunk is carried as a chunk whose sequence header and body are the bytes
	// after the security header; it serializes back to exactly the secured bytes. (Parsing it
	// would not do for CLO: the model reads a CLO request's body as empty.)
	header := readWriteModel.NewSecurityHeader(binary.LittleEndian.Uint32(secured[8:12]), binary.LittleEndian.Uint32(secured[12:16]))
	payload := readWriteModel.NewBinaryPayload(
		readWriteModel.NewSequenceHeader(int32(binary.LittleEndian.Uint32(secured[16:20])), int32(binary.LittleEndian.Uint32(secured[20:24]))),
		secured[symmetricSecurityHeaderEnd+SEQUENCE_HEADER_SIZE:],
	)
	if _, isClose := message.(readWriteModel.OpcuaCloseRequest); isClose {
		return readWriteModel.NewOpcuaAPU(readWriteModel.NewOpcuaCloseRequest(message.GetChunk(), header, payload)), nil
	}
	return readWriteModel.NewOpcuaAPU(readWriteModel.NewOpcuaMessageRequest(message.GetChunk(), header, payload)), nil
}

// decodeChunk verifies and decrypts a received chunk. Chunks other than OPN and MSG
// (Acknowledge, Error) pass as they are.
func (s *SecureChannel) decodeChunk(ctx context.Context, apu readWriteModel.OpcuaAPU) (readWriteModel.OpcuaAPU, error) {
	message := apu.GetMessage()
	_, isOpen := message.(readWriteModel.OpcuaOpenResponse)
	_, isMessage := message.(readWriteModel.OpcuaMessageResponse)
	if !isOpen && !isMessage {
		return apu, nil
	}
	if !isOpen && !s.security.secured() {
		return apu, nil
	}
	received, err := apu.Serialize()
	if err != nil {
		return nil, errors.Wrap(err, "error serializing")
	}
	var opened []byte
	if isOpen {
		opened, err = s.security.openAsymmetric(received)
	} else {
		opened, err = s.security.openSymmetric(received)
	}
	if err != nil {
		return nil, err
	}
	return readWriteModel.OpcuaAPUParse(ctx, opened, true, true)
}

// serverError turns an Error message of the server into an error.
func serverError(message readWriteModel.OpcuaMessageError) error {
	statusCode := uint32(message.GetError())
	reason := ""
	if message.GetReason() != nil && message.GetReason().GetStringValue() != nil {
		reason = *message.GetReason().GetStringValue()
	}
	name := ""
	if status, ok := readWriteModel.OpcuaStatusCodeByValue(statusCode); ok {
		name = status.PLC4XEnumName() + " "
	}
	return errors.Errorf("server reported an error: %s(0x%08X) %s", name, statusCode, reason)
}

// serviceFaultError turns a ServiceFault into an error.
func serviceFaultError(fault readWriteModel.ServiceFault) error {
	statusCode := fault.GetResponseHeader().GetServiceResult().GetStatusCode()
	name := ""
	if status, ok := readWriteModel.OpcuaStatusCodeByValue(statusCode); ok {
		name = status.PLC4XEnumName() + " "
	}
	return errors.Errorf("server answered with a service fault: %s(0x%08X)", name, statusCode)
}

// exchange sends the chunks build makes for a transaction of count identifiers and waits for
// the response accept picks, decoded. build gets the first identifier, which is the request id.
func (s *SecureChannel) exchange(ctx context.Context, codec *MessageCodec, name string, count int32,
	build func(transactionId int32) ([]readWriteModel.OpcuaAPU, error),
	accept func(apu readWriteModel.OpcuaAPU, transactionId int32) bool) (readWriteModel.OpcuaAPU, error) {
	transactionId := s.channelTransactionManager.getTransactionIdentifiers(count)
	apus, err := build(transactionId)
	if err != nil {
		return nil, err
	}
	responses := make(chan readWriteModel.OpcuaAPU, 1)
	errs := make(chan error, 1)
	requestConsumer := func(transactionId int32) {
		var decodeErr error
		acceptsMessage := func(message spi.Message) bool {
			apu, ok := message.(readWriteModel.OpcuaAPU)
			if !ok {
				return false
			}
			if serverErr, ok := apu.GetMessage().(readWriteModel.OpcuaMessageError); ok {
				decodeErr = serverError(serverErr)
				return true
			}
			decoded, err := s.decodeChunk(ctx, apu)
			if err != nil {
				s.log.Debug().Err(err).Str("exchange", name).Msg("chunk does not decode")
				return false
			}
			return accept(decoded, transactionId)
		}
		handleMessage := func(message spi.Message) error {
			if decodeErr != nil {
				errs <- decodeErr
				return nil
			}
			decoded, err := s.decodeChunk(ctx, message.(readWriteModel.OpcuaAPU))
			if err != nil {
				errs <- err
				return nil
			}
			responses <- decoded
			return nil
		}
		handleError := func(err error) error {
			errs <- err
			return nil
		}
		if err := codec.SendRequest(ctx, name, apus[0], acceptsMessage, handleMessage, handleError); err != nil {
			errs <- err
			return
		}
		for _, apu := range apus[1:] {
			if err := codec.Send(ctx, name, apu); err != nil {
				errs <- err
				return
			}
		}
	}
	if err := s.channelTransactionManager.submitSpan(requestConsumer, transactionId, count); err != nil {
		return nil, errors.Wrap(err, "error submitting")
	}
	select {
	case response := <-responses:
		return response, nil
	case err := <-errs:
		return nil, errors.Wrapf(err, "%s failed", name)
	case <-ctx.Done():
		return nil, errors.Wrapf(ctx.Err(), "%s failed", name)
	}
}

// hello sends the Hello message and records the limits of the server's Acknowledge.
func (s *SecureChannel) hello(ctx context.Context, codec *MessageCodec) error {
	hello := readWriteModel.NewOpcuaHelloRequest(
		readWriteModel.ChunkType_FINAL,
		VERSION,
		readWriteModel.NewOpcuaProtocolLimits(
			DEFAULT_RECEIVE_BUFFER_SIZE,
			DEFAULT_SEND_BUFFER_SIZE,
			DEFAULT_MAX_MESSAGE_SIZE,
			DEFAULT_MAX_CHUNK_COUNT,
		),
		s.endpoint,
	)
	response, err := s.exchange(ctx, codec, "hello", 1,
		func(int32) ([]readWriteModel.OpcuaAPU, error) {
			return []readWriteModel.OpcuaAPU{readWriteModel.NewOpcuaAPU(hello)}, nil
		},
		func(apu readWriteModel.OpcuaAPU, _ int32) bool {
			_, ok := apu.GetMessage().(readWriteModel.OpcuaAcknowledgeResponse)
			return ok
		})
	if err != nil {
		return err
	}
	s.applyServerLimits(response.GetMessage().(readWriteModel.OpcuaAcknowledgeResponse).GetLimits())
	return nil
}

func expandedNodeIdOf(definition readWriteModel.ExtensionObjectDefinition) readWriteModel.ExpandedNodeId {
	return readWriteModel.NewExpandedNodeId(false, false,
		readWriteModel.NewNodeIdFourByte(0, uint16(definition.GetExtensionId())), nil, nil)
}

func serializeExtensionObject(ctx context.Context, definition readWriteModel.ExtensionObjectDefinition) (utils.WriteBufferByteBased, error) {
	buffer := utils.NewWriteBufferByteBased(utils.WithByteOrderForByteBasedBuffer(binary.LittleEndian))
	if err := readWriteModel.NewRootExtensionObject(expandedNodeIdOf(definition), definition).SerializeWithWriteBuffer(ctx, buffer); err != nil {
		return nil, errors.Wrap(err, "error serializing")
	}
	return buffer, nil
}

func parseExtensionObject(ctx context.Context, data []byte) (readWriteModel.ExtensionObjectDefinition, error) {
	extensionObject, err := readWriteModel.ExtensionObjectParseWithBuffer[readWriteModel.ExtensionObject](ctx,
		utils.NewReadBufferByteBased(data, utils.WithByteOrderForReadBufferByteBased(binary.LittleEndian)), false)
	if err != nil {
		return nil, errors.Wrap(err, "error parsing")
	}
	body := extensionObject.GetBody()
	if fault, ok := body.(readWriteModel.ServiceFault); ok {
		return nil, serviceFaultError(fault)
	}
	return body, nil
}

func byteString(value []byte) readWriteModel.PascalByteString {
	if value == nil {
		return NULL_BYTE_STRING
	}
	return readWriteModel.NewPascalByteString(int32(len(value)), value)
}

func stringOf(value string) readWriteModel.PascalString {
	if value == "" {
		return NULL_STRING
	}
	return readWriteModel.NewPascalString(&value)
}

// newRequestHeader makes the header of a request.
func (s *SecureChannel) newRequestHeader(requestHandle uint32) readWriteModel.RequestHeader {
	return readWriteModel.NewRequestHeader(
		s.getAuthenticationToken(),
		s.getCurrentDateTime(),
		requestHandle,
		0,
		NULL_STRING,
		REQUEST_TIMEOUT_LONG,
		NULL_EXTENSION_OBJECT)
}

// openChannel asks for a security token: Issue opens the channel, Renew replaces the token of
// an open one. It installs the token's keys.
func (s *SecureChannel) openChannel(ctx context.Context, codec *MessageCodec, requestType readWriteModel.SecurityTokenRequestType) error {
	nonce, err := s.security.newLocalNonce()
	if err != nil {
		return err
	}
	request := readWriteModel.NewOpenSecureChannelRequest(
		s.newRequestHeader(0),
		VERSION,
		requestType,
		s.security.mode,
		byteString(nonce),
		s.lifetime.Load())
	body, err := serializeExtensionObject(ctx, request)
	if err != nil {
		return err
	}
	channelId := int32(0)
	if requestType == readWriteModel.SecurityTokenRequestType_securityTokenRequestTypeRenew {
		channelId = int32(s.channelId.Load())
	}
	policyUri := s.security.policy.uri
	response, err := s.exchange(ctx, codec, "open_secure_channel", 1,
		func(transactionId int32) ([]readWriteModel.OpcuaAPU, error) {
			apu, err := s.encodeChunk(ctx, readWriteModel.NewOpcuaOpenRequest(
				readWriteModel.ChunkType_FINAL,
				readWriteModel.NewOpenChannelMessageRequest(
					channelId,
					readWriteModel.NewPascalString(&policyUri),
					byteString(s.security.localCertificateIfSecured()),
					byteString(s.security.remoteThumbprintIfSecured()),
				),
				readWriteModel.NewBinaryPayload(
					readWriteModel.NewSequenceHeader(transactionId, transactionId),
					body.GetBytes(),
				),
			))
			return []readWriteModel.OpcuaAPU{apu}, err
		},
		func(apu readWriteModel.OpcuaAPU, transactionId int32) bool {
			openResponse, ok := apu.GetMessage().(readWriteModel.OpcuaOpenResponse)
			return ok && openResponse.GetMessage().GetSequenceHeader().GetRequestId() == transactionId
		})
	if err != nil {
		return err
	}
	openResponse := response.GetMessage().(readWriteModel.OpcuaOpenResponse)
	payload, ok := openResponse.GetMessage().(readWriteModel.BinaryPayload)
	if !ok {
		return errors.Errorf("unexpected payload %T", openResponse.GetMessage())
	}
	responseBody, err := parseExtensionObject(ctx, payload.GetPayload())
	if err != nil {
		return err
	}
	openSecureChannelResponse, ok := responseBody.(readWriteModel.OpenSecureChannelResponse)
	if !ok {
		return errors.Errorf("unexpected response %T to OpenSecureChannel", responseBody)
	}
	token := openSecureChannelResponse.GetSecurityToken()
	var serverNonce []byte
	if nonce := openSecureChannelResponse.GetServerNonce(); nonce != nil {
		serverNonce = nonce.GetStringValue()
	}
	if err := s.security.installToken(token.GetTokenId(), serverNonce); err != nil {
		return err
	}
	// The server numbers its chunks from where it likes; the next ones follow this one.
	s.senderSequenceNumber.Store(payload.GetSequenceHeader().GetSequenceNumber())
	s.channelId.Store(token.GetChannelId())
	s.tokenId.Store(token.GetTokenId())
	if lifetime := token.GetRevisedLifetime(); lifetime > 0 {
		s.lifetime.Store(lifetime)
	}
	s.log.Debug().
		Uint32("channelId", token.GetChannelId()).
		Uint32("tokenId", token.GetTokenId()).
		Uint32("lifetime", token.GetRevisedLifetime()).
		Msg("security token issued")
	return nil
}

// call sends a service request on the channel and returns the response, or the service fault
// as an error.
func (s *SecureChannel) call(ctx context.Context, codec *MessageCodec, request readWriteModel.ExtensionObjectDefinition) (readWriteModel.ExtensionObjectDefinition, error) {
	buffer, err := serializeExtensionObject(ctx, request)
	if err != nil {
		return nil, err
	}
	responses := make(chan []byte, 1)
	errs := make(chan error, 1)
	s.submit(ctx, codec, func(err error) {
		select {
		case errs <- err:
		default:
		}
	}, func(response []byte) {
		responses <- response
	}, buffer)
	select {
	case response := <-responses:
		return parseExtensionObject(ctx, response)
	case err := <-errs:
		return nil, err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// onConnect runs the handshake on the connection's codec: Hello, OpenSecureChannel,
// CreateSession and ActivateSession. Then it keeps renewing the channel's security token.
func (s *SecureChannel) onConnect(ctx context.Context, connection *Connection) error {
	codec := connection.messageCodec
	s.codec = codec
	ctx, cancel := context.WithTimeout(ctx, HANDSHAKE_TIMEOUT)
	defer cancel()
	if err := s.hello(ctx, codec); err != nil {
		return err
	}
	if err := s.openChannel(ctx, codec, readWriteModel.SecurityTokenRequestType_securityTokenRequestTypeIssue); err != nil {
		return err
	}
	if err := s.openSession(ctx, codec); err != nil {
		return err
	}
	s.startRenewal(codec)
	return nil
}

// openSession creates and activates the session.
func (s *SecureChannel) openSession(ctx context.Context, codec *MessageCodec) error {
	clientNonce := make([]byte, SESSION_NONCE_LENGTH)
	if _, err := cryptoRandRead(clientNonce); err != nil {
		return errors.Wrap(err, "error making nonce")
	}
	applicationName := readWriteModel.NewLocalizedText(true, true, readWriteModel.NewPascalString(new("en")), APPLICATION_TEXT)
	clientDescription := readWriteModel.NewApplicationDescription(APPLICATION_URI, PRODUCT_URI, applicationName,
		readWriteModel.ApplicationType_applicationTypeClient, NULL_STRING, NULL_STRING, nil)
	response, err := s.call(ctx, codec, readWriteModel.NewCreateSessionRequest(
		s.newRequestHeader(s.getRequestHandle()),
		clientDescription,
		NULL_STRING,
		s.endpoint,
		readWriteModel.NewPascalString(&s.sessionName),
		byteString(clientNonce),
		byteString(s.security.localCertificateIfSecured()),
		SESSION_TIMEOUT,
		0,
	))
	if err != nil {
		return errors.Wrap(err, "CreateSession failed")
	}
	session, ok := response.(readWriteModel.CreateSessionResponse)
	if !ok {
		return errors.Errorf("unexpected response %T to CreateSession", response)
	}
	s.authenticationToken = session.GetAuthenticationToken().GetNodeId()

	var serverNonce []byte
	if nonce := session.GetServerNonce(); nonce != nil {
		serverNonce = nonce.GetStringValue()
	}
	sessionCertificate, err := s.sessionServerCertificate(session)
	if err != nil {
		return err
	}
	if s.security.secured() {
		signature := session.GetServerSignature()
		algorithm := ""
		if signature.GetAlgorithm() != nil && signature.GetAlgorithm().GetStringValue() != nil {
			algorithm = *signature.GetAlgorithm().GetStringValue()
		}
		if err := s.security.verifySession(clientNonce, algorithm, signature.GetSignature().GetStringValue()); err != nil {
			return err
		}
	}

	identityToken, err := s.identityToken(session.GetServerEndpoints(), serverNonce, sessionCertificate)
	if err != nil {
		return err
	}
	algorithm, signature, err := s.security.signSession(serverNonce)
	if err != nil {
		return err
	}
	requestHandle := s.getRequestHandle()
	response, err = s.call(ctx, codec, readWriteModel.NewActivateSessionRequest(
		s.newRequestHeader(requestHandle),
		readWriteModel.NewSignatureData(stringOf(algorithm), byteString(signature)),
		nil,
		nil,
		identityToken,
		readWriteModel.NewSignatureData(NULL_STRING, NULL_BYTE_STRING),
	))
	if err != nil {
		return errors.Wrap(err, "ActivateSession failed")
	}
	activated, ok := response.(readWriteModel.ActivateSessionResponse)
	if !ok {
		return errors.Errorf("unexpected response %T to ActivateSession", response)
	}
	if returned := activated.GetResponseHeader().GetRequestHandle(); returned != requestHandle {
		s.log.Warn().Uint32("requestHandle", requestHandle).Uint32("returnedRequestHandle", returned).Msg("ActivateSession answered another request handle")
	}
	s.log.Info().Str("securityPolicy", s.security.policy.name).Stringer("mode", s.security.mode).Msg("session activated")
	return nil
}

// sessionServerCertificate is the certificate the server sent with CreateSession. On a secured
// channel it must be the one the channel was opened with.
func (s *SecureChannel) sessionServerCertificate(session readWriteModel.CreateSessionResponse) (*x509.Certificate, error) {
	var raw []byte
	if certificate := session.GetServerCertificate(); certificate != nil {
		raw = certificate.GetStringValue()
	}
	if len(raw) == 0 {
		if s.security.secured() {
			return nil, errors.New("server sent no certificate with CreateSession")
		}
		return nil, nil
	}
	certificates, err := x509.ParseCertificates(raw)
	if err != nil || len(certificates) == 0 {
		if s.security.secured() {
			return nil, errors.Wrap(err, "error parsing the server's session certificate")
		}
		return nil, nil
	}
	if s.serverCertificate != nil && !certificates[0].Equal(s.serverCertificate) {
		return nil, errors.New("server's session certificate is not the one the channel was opened with")
	}
	return certificates[0], nil
}

// identityToken makes the user identity token for ActivateSession: anonymous without a
// username, otherwise a username token whose password is encrypted with the server's key as
// the token policy says.
func (s *SecureChannel) identityToken(endpoints []readWriteModel.EndpointDescription, serverNonce []byte, serverCertificate *x509.Certificate) (readWriteModel.ExtensionObject, error) {
	wanted := readWriteModel.UserTokenType_userTokenTypeAnonymous
	if s.username != "" {
		wanted = readWriteModel.UserTokenType_userTokenTypeUserName
	}
	tokenPolicy := s.findUserTokenPolicy(endpoints, wanted)
	if tokenPolicy == nil {
		return nil, errors.Errorf("server offers no %s login on an endpoint with security policy %s and mode %s", wanted, s.security.policy.name, s.security.mode)
	}
	wrap := func(token readWriteModel.ExtensionObjectDefinition) readWriteModel.ExtensionObject {
		return readWriteModel.NewBinaryExtensionObjectWithMask(expandedNodeIdOf(token), BINARY_ENCODING_MASK, token)
	}
	if wanted == readWriteModel.UserTokenType_userTokenTypeAnonymous {
		return wrap(readWriteModel.NewAnonymousIdentityToken(tokenPolicy.GetPolicyId())), nil
	}

	// The password goes encrypted with the token policy's security policy, or the channel's
	// when the token policy names none.
	passwordPolicy := s.security.policy
	if uri := tokenPolicy.GetSecurityPolicyUri(); uri != nil && uri.GetStringValue() != nil && *uri.GetStringValue() != "" {
		var err error
		if passwordPolicy, err = securityPolicyByName(*uri.GetStringValue()); err != nil {
			return nil, err
		}
	}
	password := []byte(s.password)
	algorithm := ""
	if passwordPolicy.isNone() {
		if !s.security.encrypted() && !s.configuration.AllowInsecureCredentials {
			return nil, errors.New("the server would receive the password unencrypted: use a security policy with SIGN_ENCRYPT, or set allow-insecure-credentials=true")
		}
	} else {
		if serverCertificate == nil {
			return nil, errors.New("the server sent no certificate to encrypt the password with")
		}
		publicKey, ok := serverCertificate.PublicKey.(*rsa.PublicKey)
		if !ok {
			return nil, errors.Errorf("the server's %T key cannot encrypt the password", serverCertificate.PublicKey)
		}
		plain := binary.LittleEndian.AppendUint32(nil, uint32(len(password)+len(serverNonce)))
		plain = append(plain, password...)
		plain = append(plain, serverNonce...)
		encrypted, err := passwordPolicy.asymmetricEncryptAll(publicKey, plain)
		if err != nil {
			return nil, errors.Wrap(err, "error encrypting the password")
		}
		password = encrypted
		algorithm = passwordPolicy.asymmetricEncryptionURI()
	}
	return wrap(readWriteModel.NewUserNameIdentityToken(
		tokenPolicy.GetPolicyId(),
		readWriteModel.NewPascalString(&s.username),
		byteString(password),
		stringOf(algorithm),
	)), nil
}

// findUserTokenPolicy finds a user token policy of the wanted type, on an endpoint with the
// channel's security policy and mode if the server has one, otherwise on any endpoint.
func (s *SecureChannel) findUserTokenPolicy(endpoints []readWriteModel.EndpointDescription, wanted readWriteModel.UserTokenType) readWriteModel.UserTokenPolicy {
	var fallback readWriteModel.UserTokenPolicy
	for _, endpoint := range endpoints {
		matches := endpoint.GetSecurityMode() == s.security.mode &&
			endpoint.GetSecurityPolicyUri() != nil && endpoint.GetSecurityPolicyUri().GetStringValue() != nil &&
			*endpoint.GetSecurityPolicyUri().GetStringValue() == s.security.policy.uri
		for _, policy := range endpoint.GetUserIdentityTokens() {
			if policy.GetTokenType() != wanted {
				continue
			}
			if matches {
				return policy
			}
			if fallback == nil {
				fallback = policy
			}
		}
	}
	return fallback
}

// startRenewal renews the channel's security token at three quarters of its lifetime, until
// the channel closes.
func (s *SecureChannel) startRenewal(codec *MessageCodec) {
	stop := make(chan struct{})
	s.renewal = stop
	s.renewalWg.Go(func() {
		for {
			wait := time.Duration(float64(s.lifetime.Load())*0.75) * time.Millisecond
			select {
			case <-stop:
				return
			case <-time.After(wait):
			}
			if !codec.IsRunning() {
				return
			}
			ctx, cancel := context.WithTimeout(context.Background(), HANDSHAKE_TIMEOUT)
			err := s.openChannel(ctx, codec, readWriteModel.SecurityTokenRequestType_securityTokenRequestTypeRenew)
			cancel()
			if err != nil {
				s.log.Error().Err(err).Msg("renewing the security token failed")
			}
		}
	})
}

func (s *SecureChannel) stopRenewal() {
	if s.renewal != nil {
		close(s.renewal)
		s.renewal = nil
	}
	s.renewalWg.Wait()
}

// onDisconnect closes the session and the secure channel.
func (s *SecureChannel) onDisconnect(ctx context.Context, connection *Connection) {
	s.log.Info().Msg("disconnecting")
	s.stopRenewal()
	codec := connection.messageCodec
	if s.authenticationToken != nil {
		if _, err := s.call(ctx, codec, readWriteModel.NewCloseSessionRequest(s.newRequestHeader(s.getRequestHandle()), true)); err != nil {
			s.log.Debug().Err(err).Msg("CloseSession failed")
		}
	}
	if err := s.closeChannel(ctx, codec); err != nil {
		s.log.Debug().Err(err).Msg("CloseSecureChannel failed")
	}
}

// closeChannel sends CloseSecureChannel. The server answers by closing the connection.
func (s *SecureChannel) closeChannel(ctx context.Context, codec *MessageCodec) error {
	body, err := serializeExtensionObject(ctx, readWriteModel.NewCloseSecureChannelRequest(s.newRequestHeader(0)))
	if err != nil {
		return err
	}
	transactionId := s.channelTransactionManager.getTransactionIdentifier()
	apu, err := s.encodeChunk(ctx, readWriteModel.NewOpcuaCloseRequest(
		readWriteModel.ChunkType_FINAL,
		readWriteModel.NewSecurityHeader(s.channelId.Load(), s.tokenId.Load()),
		readWriteModel.NewBinaryPayload(
			readWriteModel.NewSequenceHeader(transactionId, transactionId),
			body.GetBytes(),
		),
	))
	if err != nil {
		return err
	}
	errs := make(chan error, 1)
	if err := s.channelTransactionManager.submit(func(int32) {
		errs <- codec.Send(ctx, "close_secure_channel", apu)
	}, transactionId); err != nil {
		return err
	}
	select {
	case err := <-errs:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *SecureChannel) submit(ctx context.Context, codec *MessageCodec, errorDispatcher func(err error), consumer func(opcuaResponse []byte), buffer utils.WriteBufferByteBased) {
	// A message larger than the server's receive buffer goes out in several chunks. Each chunk
	// has its own sequence number, so the message reserves one transaction identifier per chunk:
	// the first one is also the request id the response carries.
	bodies, err := s.splitBody(buffer.GetBytes())
	if err != nil {
		errorDispatcher(err)
		return
	}
	transactionId := s.channelTransactionManager.getTransactionIdentifiers(int32(len(bodies)))

	apus := make([]readWriteModel.OpcuaAPU, 0, len(bodies))
	for i, body := range bodies {
		chunkType := readWriteModel.ChunkType_CONTINUE
		if i == len(bodies)-1 {
			chunkType = readWriteModel.ChunkType_FINAL
		}
		apu, err := s.encodeChunk(ctx, readWriteModel.NewOpcuaMessageRequest(
			chunkType,
			readWriteModel.NewSecurityHeader(
				s.channelId.Load(),
				s.tokenId.Load(),
			),
			readWriteModel.NewBinaryPayload(
				readWriteModel.NewSequenceHeader(transactionId+int32(i), transactionId),
				body,
			),
		))
		if err != nil {
			errorDispatcher(err)
			return
		}
		apus = append(apus, apu)
	}

	requestConsumer := func(transactionId int32) {
		// The response may come in several chunks too: the expectation keeps collecting chunks
		// of this request until the final one (or an abort) arrives.
		var assembler chunkAssembler
		var responseErr error
		acceptsMessage := func(message spi.Message) bool {
			opcuaAPU, ok := message.(readWriteModel.OpcuaAPU)
			if !ok {
				s.log.Debug().Type("type", message).Msg("Not relevant")
				return false
			}
			if _, ok := opcuaAPU.GetMessage().(readWriteModel.OpcuaMessageResponse); !ok {
				return false
			}
			decoded, err := s.decodeChunk(ctx, opcuaAPU)
			if err != nil {
				s.log.Debug().Err(err).Msg("chunk does not decode")
				return false
			}
			opcuaResponse := decoded.GetMessage().(readWriteModel.OpcuaMessageResponse)
			if requestId := opcuaResponse.GetMessage().GetSequenceHeader().GetRequestId(); requestId != transactionId {
				s.log.Trace().Int32("requestId", requestId).Int32("transactionId", transactionId).Msg("Not relevant")
				return false
			}
			if expected, got := s.senderSequenceNumber.Add(1), opcuaResponse.GetMessage().GetSequenceHeader().GetSequenceNumber(); expected != got {
				s.log.Warn().
					Int32("expectedSequenceNumber", expected).
					Int32("responseSequenceNumber", got).
					Msg("Sequence number isn't as expected, we might have missed a packet")
				s.senderSequenceNumber.Store(got)
			}
			payload, ok := opcuaResponse.GetMessage().(readWriteModel.BinaryPayload)
			if !ok {
				responseErr = errors.Errorf("unexpected payload %T", opcuaResponse.GetMessage())
				return true
			}
			switch opcuaResponse.GetChunk() {
			case readWriteModel.ChunkType_CONTINUE:
				if err := assembler.add(payload.GetPayload()); err != nil {
					responseErr = err
					return true
				}
				s.log.Trace().Int("chunks", len(assembler.parts)).Msg("collected chunk")
				return false // wait for the next chunk of this response
			case readWriteModel.ChunkType_ABORT:
				responseErr = abortError(payload.GetPayload())
				return true
			default:
				if err := assembler.add(payload.GetPayload()); err != nil {
					responseErr = err
				}
				return true
			}
		}
		handleMessage := func(spi.Message) error {
			if responseErr != nil {
				errorDispatcher(responseErr)
				return nil
			}
			consumer(assembler.message())
			return nil
		}
		handleError := func(err error) error {
			errorDispatcher(err)
			return nil
		}
		// The expectation goes in with the first chunk: a server may answer before the last
		// chunk of the request has been written (to abort it, say).
		if err := codec.SendRequest(ctx, "submis", apus[0], acceptsMessage, handleMessage, handleError); err != nil {
			errorDispatcher(err)
			return
		}
		for _, apu := range apus[1:] {
			if err := codec.Send(ctx, "submis", apu); err != nil {
				errorDispatcher(err)
				return
			}
		}
	}

	s.log.Debug().Int32("transactionId", transactionId).Int("chunks", len(apus)).Msg("Submitting Transaction to TransactionManager")
	if err := s.channelTransactionManager.submitSpan(requestConsumer, transactionId, int32(len(apus))); err != nil {
		s.log.Debug().Err(err).Msg("error submitting")
	}
}

// getRequestHandle returns the next request handle
func (s *SecureChannel) getRequestHandle() uint32 {
	return s.requestHandleGenerator.Add(1) - 1
}

// getAuthenticationToken returns the authentication token for the current connection
func (s *SecureChannel) getAuthenticationToken() readWriteModel.NodeId {
	if s.authenticationToken == nil {
		panic("authenticationToken should be set at this point")
	}
	return readWriteModel.NewNodeId(s.authenticationToken)
}

// getChannelId gets the Channel identifier for the current channel
func (s *SecureChannel) getChannelId() uint32 {
	return s.channelId.Load()
}

// getTokenId gets the Token Identifier
func (s *SecureChannel) getTokenId() uint32 {
	return s.tokenId.Load()
}

func (s *SecureChannel) getCurrentDateTime() int64 {
	return (time.Now().UnixMilli() * 10000) + EPOCH_OFFSET
}
