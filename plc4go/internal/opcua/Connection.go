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
	"crypto/x509"
	"slices"
	"sync"
	"time"

	"github.com/rs/zerolog"

	plc4go "github.com/apache/plc4x/plc4go/pkg/api"
	apiModel "github.com/apache/plc4x/plc4go/pkg/api/model"
	"github.com/apache/plc4x/plc4go/spi"
	_default "github.com/apache/plc4x/plc4go/spi/default"
	"github.com/apache/plc4x/plc4go/spi/errors"
	spiModel "github.com/apache/plc4x/plc4go/spi/model"
	"github.com/apache/plc4x/plc4go/spi/options"
	"github.com/apache/plc4x/plc4go/spi/tracer"
)

//go:generate go tool plc4xGenerator -type=Connection
type Connection struct {
	_default.DefaultConnection

	messageCodec *MessageCodec
	subscribers  []*Subscriber

	configuration Configuration `stringer:"true"`
	driverContext DriverContext `stringer:"true"`

	channel *SecureChannel
	// newDiscoveryCodec opens another connection to the server, for discovering its endpoints.
	newDiscoveryCodec func() (*MessageCodec, error) `ignore:"true"`

	connectEvent      chan struct{}
	connectTimeout    time.Duration // TODO: do we need to have that in general, where to get that from
	disconnectEvent   chan struct{}
	disconnectTimeout time.Duration // TODO: do we need to have that in general, where to get that from

	connectionId string
	tracer       tracer.Tracer

	wg sync.WaitGroup // use to track spawned go routines

	log      zerolog.Logger       `ignore:"true"`
	_options []options.WithOption `ignore:"true"` // Used to pass them downstream
}

var (
	_ spi.TransportInstanceExposer = (*Connection)(nil)
)

func NewConnection(messageCodec *MessageCodec, configuration Configuration, driverContext DriverContext, tagHandler spi.PlcTagHandler, connectionOptions map[string][]string, _options ...options.WithOption) *Connection {
	customLogger := options.ExtractCustomLoggerOrDefaultToGlobal(_options...)
	connection := &Connection{
		messageCodec:      messageCodec,
		configuration:     configuration,
		driverContext:     driverContext,
		channel:           NewSecureChannel(customLogger, driverContext, configuration),
		connectEvent:      make(chan struct{}),
		connectTimeout:    5 * time.Second,
		disconnectEvent:   make(chan struct{}),
		disconnectTimeout: 5 * time.Second,
		log:               customLogger,
		_options:          _options,
	}
	if traceEnabledOption, ok := connectionOptions["traceEnabled"]; ok {
		if len(traceEnabledOption) == 1 {
			connection.tracer = tracer.NewTracer(connection.connectionId, _options...)
		}
	}
	connection.DefaultConnection = _default.NewDefaultConnection(
		connection,
		append(_options,
			_default.WithPlcTagHandler(tagHandler),
		)...,
	)
	return connection
}

func (c *Connection) GetConnectionId() string {
	return c.connectionId
}

func (c *Connection) IsTraceEnabled() bool {
	return c.tracer != nil
}

func (c *Connection) GetTracer() tracer.Tracer {
	return c.tracer
}

func (c *Connection) GetConnection() plc4go.PlcConnection {
	return c
}

func (c *Connection) GetMessageCodec() spi.MessageCodec {
	return c.messageCodec
}

func (c *Connection) Connect(ctx context.Context) error {
	c.log.Trace().Msg("Connecting")
	if err := c.prepareSecurity(ctx); err != nil {
		return errors.Wrap(err, "Error preparing the secure channel")
	}
	c.log.Trace().Msg("connecting codec")
	if err := c.messageCodec.Connect(ctx); err != nil {
		return errors.Wrap(err, "Error connecting codec")
	}

	// For testing purposes we can skip the waiting for a complete connection
	if !c.driverContext.awaitSetupComplete {
		c.wg.Go(func() {
			if err := c.setupConnection(ctx); err != nil {
				c.log.Error().Err(err).Msg("Error during setup")
			}
		})
		c.log.Warn().Msg("Connection used in an unsafe way. !!!DON'T USE IN PRODUCTION!!!")
		// Here we write directly and don't wait till the connection is "really" connected
		// Note: we can't use fireConnected here as it's guarded against m.driverContext.awaitSetupComplete
		c.SetConnected(true)
		return nil
	}

	if err := c.setupConnection(ctx); err != nil {
		return errors.Wrap(err, "Error setting up connection")
	}
	return nil
}

// prepareSecurity gives the channel what its security policy needs: the client's certificate
// and key, and the server's certificate - pinned with server-certificate-file or discovered on
// a connection of its own - once it is trusted.
func (c *Connection) prepareSecurity(ctx context.Context) error {
	policy, err := c.configuration.securityPolicy()
	if err != nil {
		return err
	}
	if policy.isNone() {
		return c.channel.prepareSecurity(clientIdentity{}, nil)
	}
	if c.configuration.KeyStoreFile != "" {
		return errors.New("tls.keystore (a PKCS#12 key store) is not supported by this driver: " +
			"put the client certificate and key as PEM files into cert-directory instead")
	}
	identity, err := loadClientIdentity(c.log, c.configuration.CertDirectory, c.configuration.GeneratedKeySize, *APPLICATION_URI.GetStringValue())
	if err != nil {
		return errors.Wrap(err, "error loading the client certificate")
	}
	trust, err := newServerTrust(c.log, c.configuration)
	if err != nil {
		return err
	}
	var chain []*x509.Certificate
	switch {
	case trust.pinned != nil:
		chain = []*x509.Certificate{trust.pinned}
	case !c.configuration.Discovery:
		return errors.Errorf("security policy %s needs the server's certificate: name it with server-certificate-file, or turn discovery on", policy.name)
	case c.newDiscoveryCodec == nil:
		return errors.New("no way to open a discovery connection")
	default:
		codec, err := c.newDiscoveryCodec()
		if err != nil {
			return errors.Wrap(err, "error opening the discovery connection")
		}
		if chain, err = discoverServerCertificate(ctx, c.log, c.configuration, codec); err != nil {
			return err
		}
	}
	if err := trust.verify(chain); err != nil {
		return errors.Wrap(err, "the server's certificate is not trusted")
	}
	return c.channel.prepareSecurity(identity, chain[0])
}

func (c *Connection) Close() error {
	ctx, cancelFunc := context.WithTimeout(context.Background(), c.disconnectTimeout)
	defer cancelFunc()
	c.channel.onDisconnect(ctx, c)
	if err := c.messageCodec.Disconnect(); err != nil {
		c.log.Debug().Err(err).Msg("Error disconnecting message codec")
	}
	c.SetConnected(false)
	c.log.Info().Msg("disconnected")
	return nil
}

func (c *Connection) GetMetadata() apiModel.PlcConnectionMetadata {
	return &_default.DefaultConnectionMetadata{
		ProvidesReading:     true,
		ProvidesWriting:     true,
		ProvidesSubscribing: true,
		ProvidesBrowsing:    false,
	}
}

func (c *Connection) ReadRequestBuilder() apiModel.PlcReadRequestBuilder {
	return spiModel.NewDefaultPlcReadRequestBuilder(
		c.GetPlcTagHandler(),
		NewReader(
			c,
			append(c._options, options.WithCustomLogger(c.log))...,
		),
	)
}

func (c *Connection) WriteRequestBuilder() apiModel.PlcWriteRequestBuilder {
	return spiModel.NewDefaultPlcWriteRequestBuilder(c.GetPlcTagHandler(), c.GetPlcValueHandler(), NewWriter(c))
}

func (c *Connection) SubscriptionRequestBuilder() apiModel.PlcSubscriptionRequestBuilder {
	return spiModel.NewDefaultPlcSubscriptionRequestBuilder(
		c.GetPlcTagHandler(),
		c.GetPlcValueHandler(),
		NewSubscriber(
			c.addSubscriber,
			c,
			append(c._options, options.WithCustomLogger(c.log))...,
		),
	)
}

func (c *Connection) UnsubscriptionRequestBuilder() apiModel.PlcUnsubscriptionRequestBuilder {
	// TODO: where do we get the unsubscriber from
	return nil
}

func (c *Connection) addSubscriber(subscriber *Subscriber) {
	if slices.Contains(c.subscribers, subscriber) {
		c.log.Debug().Interface("subscriber", subscriber).Msg("Subscriber already added")
		return
	}
	c.subscribers = append(c.subscribers, subscriber)
}

func (c *Connection) setupConnection(ctx context.Context) error {
	c.log.Trace().Msg("setup connection")
	if err := c.channel.onConnect(ctx, c); err != nil {
		c.fireConnectionError(err, make(chan error, 1))
		return errors.Wrap(err, "Error during connection setup")
	}
	c.fireConnected(make(chan struct{}, 1))
	c.log.Trace().Msg("connection setup done")
	return nil
}

func (c *Connection) fireConnectionError(err error, ch chan<- error) {
	c.log.Trace().Err(err).Msg("fire connection error")
	if c.driverContext.awaitSetupComplete {
		ch <- errors.Wrap(err, "Error during connection")
	} else {
		c.log.Error().Err(err).Msg("awaitSetupComplete set to false and we got a error during connect")
	}
	if err := c.messageCodec.Disconnect(); err != nil {
		c.log.Debug().Err(err).Msg("Error disconnecting message codec on connection error")
	}
	c.SetConnected(false)
	select {
	case c.disconnectEvent <- struct{}{}:
	default:
	}
}

func (c *Connection) fireConnected(ch chan<- struct{}) {
	c.log.Trace().Msg("fire connected")
	if c.driverContext.awaitSetupComplete {
		ch <- struct{}{}
	} else {
		c.log.Info().Msg("Successfully connected")
	}
	c.SetConnected(true)
	select {
	case c.connectEvent <- struct{}{}:
	default:
	}
}
