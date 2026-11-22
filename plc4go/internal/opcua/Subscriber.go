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
	"runtime/debug"
	"sync"
	"time"

	"github.com/rs/zerolog"

	apiModel "github.com/apache/plc4x/plc4go/pkg/api/model"
	readWriteModel "github.com/apache/plc4x/plc4go/protocols/opcua/readwrite/model"
	"github.com/apache/plc4x/plc4go/spi/errors"
	spiModel "github.com/apache/plc4x/plc4go/spi/model"
	"github.com/apache/plc4x/plc4go/spi/options"
	"github.com/apache/plc4x/plc4go/spi/utils"
)

//go:generate go tool plc4xGenerator -type=Subscriber
type Subscriber struct {
	consumers     map[*spiModel.DefaultPlcConsumerRegistration]apiModel.PlcSubscriptionEventConsumer
	addSubscriber func(subscriber *Subscriber)
	connection    *Connection
	subscriptions map[uint32]*SubscriptionHandle `ignore:"true"` // TODO: we don't have support for non string key maps yet

	consumersMutex     sync.RWMutex
	subscriptionsMutex sync.Mutex

	log      zerolog.Logger       `ignore:"true"`
	_options []options.WithOption `ignore:"true"` // Used to pass them downstream
}

func NewSubscriber(addSubscriber func(subscriber *Subscriber), connection *Connection, _options ...options.WithOption) *Subscriber {
	customLogger := options.ExtractCustomLoggerOrDefaultToGlobal(_options...)
	return &Subscriber{
		consumers:     make(map[*spiModel.DefaultPlcConsumerRegistration]apiModel.PlcSubscriptionEventConsumer),
		addSubscriber: addSubscriber,
		connection:    connection,
		subscriptions: map[uint32]*SubscriptionHandle{},

		log:      customLogger,
		_options: _options,
	}
}

func (s *Subscriber) Subscribe(ctx context.Context, subscriptionRequest apiModel.PlcSubscriptionRequest) <-chan apiModel.PlcSubscriptionRequestResult {
	result := make(chan apiModel.PlcSubscriptionRequestResult, 1)
	go s.subscribeSync(ctx, result, subscriptionRequest)
	return result
}

func (s *Subscriber) subscribeSync(ctx context.Context, result chan apiModel.PlcSubscriptionRequestResult, subscriptionRequest apiModel.PlcSubscriptionRequest) {
	defer func() {
		if err := recover(); err != nil {
			utils.DeliverResult(s.log, result, spiModel.NewDefaultPlcSubscriptionRequestResult(subscriptionRequest, nil, errors.Errorf("panic-ed %v. Stack: %s", err, debug.Stack())))
		}
	}()
	fail := func(err error) {
		utils.DeliverResult(s.log, result, spiModel.NewDefaultPlcSubscriptionRequestResult(subscriptionRequest, nil, err))
	}
	internalPlcSubscriptionRequest := subscriptionRequest.(*spiModel.DefaultPlcSubscriptionRequest)
	tagNames := internalPlcSubscriptionRequest.GetTagNames()
	if len(tagNames) == 0 {
		fail(errors.New("no tags to subscribe to"))
		return
	}

	// The subscription publishes at the shortest interval its tags ask for.
	cycleTime := time.Duration(0)
	for _, name := range tagNames {
		if interval := internalPlcSubscriptionRequest.GetInterval(name); interval > 0 && (cycleTime == 0 || interval < cycleTime) {
			cycleTime = interval
		}
	}
	if cycleTime == 0 {
		cycleTime = SUBSCRIPTION_DEFAULT_INTERVAL
	}

	subscription, err := s.onSubscribeCreateSubscription(ctx, cycleTime)
	if err != nil {
		fail(errors.Wrap(err, "error creating the subscription"))
		return
	}
	subscriptionId := subscription.GetSubscriptionId()
	revisedCycleTime := time.Duration(subscription.GetRevisedPublishingInterval() * float64(time.Millisecond))
	if revisedCycleTime <= 0 {
		revisedCycleTime = cycleTime
	}
	keepAliveCount := subscription.GetRevisedMaxKeepAliveCount()
	if keepAliveCount == 0 {
		keepAliveCount = SUBSCRIPTION_KEEP_ALIVE_COUNT
	}
	handle, err := NewSubscriptionHandle(s.log, s, s.connection, subscriptionRequest, subscriptionId, cycleTime, revisedCycleTime, keepAliveCount)
	if err != nil {
		s.deleteSubscription(subscriptionId)
		fail(err)
		return
	}
	s.subscriptionsMutex.Lock()
	s.subscriptions[subscriptionId] = handle
	s.subscriptionsMutex.Unlock()

	// Add this subscriber to the connection.
	s.addSubscriber(s)

	responseCodes := handle.responseCodes()
	subscriptionValues := make(map[string]apiModel.PlcSubscriptionHandle)
	for _, tagName := range tagNames {
		for _, consumer := range internalPlcSubscriptionRequest.GetPreRegisteredConsumers(tagName) {
			_ = handle.Register(consumer)
		}
		subscriptionValues[tagName] = handle
	}
	handle.startSubscriber()

	utils.DeliverResult(s.log, result, spiModel.NewDefaultPlcSubscriptionRequestResult(
		subscriptionRequest,
		spiModel.NewDefaultPlcSubscriptionResponse(
			subscriptionRequest,
			responseCodes,
			subscriptionValues,
			append(s._options, options.WithCustomLogger(s.log))...,
		),
		nil,
	))
}

// onSubscribeCreateSubscription creates a subscription publishing every cycleTime.
func (s *Subscriber) onSubscribeCreateSubscription(ctx context.Context, cycleTime time.Duration) (readWriteModel.CreateSubscriptionResponse, error) {
	channel := s.connection.channel
	ctx, cancel := context.WithTimeout(ctx, REQUEST_TIMEOUT_LONG*time.Millisecond)
	defer cancel()
	response, err := channel.call(ctx, s.connection.messageCodec, readWriteModel.NewCreateSubscriptionRequest(
		channel.newRequestHeader(channel.getRequestHandle()),
		float64(cycleTime)/float64(time.Millisecond),
		SUBSCRIPTION_LIFETIME_COUNT,
		SUBSCRIPTION_KEEP_ALIVE_COUNT,
		0, // as many notifications per Publish as there are
		true,
		0,
	))
	if err != nil {
		return nil, err
	}
	created, ok := response.(readWriteModel.CreateSubscriptionResponse)
	if !ok {
		return nil, errors.Errorf("unexpected response %T to CreateSubscription", response)
	}
	return created, nil
}

// deleteSubscription deletes a subscription that never got a handle.
func (s *Subscriber) deleteSubscription(subscriptionId uint32) {
	channel := s.connection.channel
	ctx, cancel := context.WithTimeout(context.Background(), REQUEST_TIMEOUT_LONG*time.Millisecond)
	defer cancel()
	if _, err := channel.call(ctx, s.connection.messageCodec, readWriteModel.NewDeleteSubscriptionsRequest(
		channel.newRequestHeader(channel.getRequestHandle()), []uint32{subscriptionId})); err != nil {
		s.log.Debug().Err(err).Msg("DeleteSubscriptions failed")
	}
}

// subscriptionEnded forgets a subscription the server ended.
func (s *Subscriber) subscriptionEnded(handle *SubscriptionHandle) {
	s.subscriptionsMutex.Lock()
	delete(s.subscriptions, handle.subscriptionId)
	s.subscriptionsMutex.Unlock()
	handle.cancel()
}

// stopAll deletes the subscriber's subscriptions, before the connection closes.
func (s *Subscriber) stopAll() {
	s.subscriptionsMutex.Lock()
	handles := make([]*SubscriptionHandle, 0, len(s.subscriptions))
	for id, handle := range s.subscriptions {
		handles = append(handles, handle)
		delete(s.subscriptions, id)
	}
	s.subscriptionsMutex.Unlock()
	for _, handle := range handles {
		handle.stopSubscriber()
	}
}

func (s *Subscriber) onDisconnect() {
	ctx := context.TODO()
	s.log.Trace().Msg("disconnecting")
	s.stopAll()
	s.connection.channel.onDisconnect(ctx, s.connection)
}

// Unsubscribe deletes the subscriptions of the handles.
func (s *Subscriber) Unsubscribe(ctx context.Context, unsubscriptionRequest apiModel.PlcUnsubscriptionRequest) <-chan apiModel.PlcUnsubscriptionRequestResult {
	result := make(chan apiModel.PlcUnsubscriptionRequestResult, 1)
	go func() {
		for _, handle := range unsubscriptionRequest.(*spiModel.DefaultPlcUnsubscriptionRequest).GetSubscriptionHandles() {
			if h, ok := handle.(*SubscriptionHandle); ok && h.plcSubscriber == s {
				s.subscriptionsMutex.Lock()
				delete(s.subscriptions, h.subscriptionId)
				s.subscriptionsMutex.Unlock()
				h.stopSubscriber()
			}
		}
		utils.DeliverResult(s.log, result, spiModel.NewDefaultPlcUnsubscriptionRequestResult(unsubscriptionRequest, spiModel.NewDefaultPlcUnsubscriptionResponse(unsubscriptionRequest), nil))
	}()
	return result
}

func (s *Subscriber) Register(consumer apiModel.PlcSubscriptionEventConsumer, handles []apiModel.PlcSubscriptionHandle) apiModel.PlcConsumerRegistration {
	s.consumersMutex.Lock()
	defer s.consumersMutex.Unlock()
	consumerRegistration := spiModel.NewDefaultPlcConsumerRegistration(s, consumer, handles...)
	s.consumers[consumerRegistration.(*spiModel.DefaultPlcConsumerRegistration)] = consumer
	return consumerRegistration
}

// consumersOf are the consumers registered on a handle.
func (s *Subscriber) consumersOf(handle *SubscriptionHandle) []apiModel.PlcSubscriptionEventConsumer {
	s.consumersMutex.RLock()
	defer s.consumersMutex.RUnlock()
	var out []apiModel.PlcSubscriptionEventConsumer
	for registration, consumer := range s.consumers {
		for _, h := range registration.GetSubscriptionHandles() {
			if h == apiModel.PlcSubscriptionHandle(handle) {
				out = append(out, consumer)
				break
			}
		}
	}
	return out
}

func (s *Subscriber) Unregister(registration apiModel.PlcConsumerRegistration) {
	s.consumersMutex.Lock()
	defer s.consumersMutex.Unlock()
	delete(s.consumers, registration.(*spiModel.DefaultPlcConsumerRegistration))
}
