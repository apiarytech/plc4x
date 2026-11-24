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
	"sync"
	"time"

	"github.com/rs/zerolog"

	apiModel "github.com/apache/plc4x/plc4go/pkg/api/model"
	readWriteModel "github.com/apache/plc4x/plc4go/protocols/opcua/readwrite/model"
	"github.com/apache/plc4x/plc4go/spi/errors"
	spiModel "github.com/apache/plc4x/plc4go/spi/model"
)

// Timing of a subscription (OPC UA Part 4, 5.13.2): the server answers a Publish request at
// least every keep-alive count publishing intervals, and drops the subscription after the
// lifetime count without one.
const (
	SUBSCRIPTION_KEEP_ALIVE_COUNT = 10
	SUBSCRIPTION_LIFETIME_COUNT   = 60
	SUBSCRIPTION_DEFAULT_INTERVAL = time.Second
	// PUBLISH_REQUESTS is how many Publish requests wait at the server, so a notification goes
	// out while the answer to the previous one is on its way.
	PUBLISH_REQUESTS = 2
)

// SubscriptionHandle is one OPC UA subscription with a monitored item per tag. It keeps
// Publish requests waiting at the server and hands the data changes they bring to the
// consumers registered on it.
type SubscriptionHandle struct {
	*spiModel.DefaultPlcSubscriptionHandle
	plcSubscriber       *Subscriber
	connection          *Connection
	subscriptionRequest apiModel.PlcSubscriptionRequest
	tagNames            []string
	subscriptionId      uint32
	cycleTime           time.Duration
	revisedCycleTime    time.Duration
	keepAliveCount      uint32

	mutex         sync.Mutex
	clientHandles map[uint32]string // the tag of each monitored item's client handle
	results       map[string]apiModel.PlcResponseCode
	acks          []readWriteModel.SubscriptionAcknowledgement

	ctx          context.Context
	cancel       context.CancelFunc
	stopOnce     sync.Once
	subscriberWg sync.WaitGroup

	log zerolog.Logger
}

// NewSubscriptionHandle makes the handle of subscription subscriptionId and creates its
// monitored items.
func NewSubscriptionHandle(log zerolog.Logger, subscriber *Subscriber, connection *Connection, subscriptionRequest apiModel.PlcSubscriptionRequest, subscriptionId uint32, cycleTime, revisedCycleTime time.Duration, keepAliveCount uint32) (*SubscriptionHandle, error) {
	ctx, cancel := context.WithCancel(context.Background())
	h := &SubscriptionHandle{
		plcSubscriber:       subscriber,
		connection:          connection,
		subscriptionRequest: subscriptionRequest,
		tagNames:            subscriptionRequest.GetTagNames(),
		subscriptionId:      subscriptionId,
		cycleTime:           cycleTime,
		revisedCycleTime:    revisedCycleTime,
		keepAliveCount:      keepAliveCount,
		clientHandles:       map[uint32]string{},
		results:             map[string]apiModel.PlcResponseCode{},
		ctx:                 ctx,
		cancel:              cancel,
		log:                 log,
	}
	h.DefaultPlcSubscriptionHandle = spiModel.NewDefaultPlcSubscriptionHandleWithHandleToRegister(subscriber, h)
	if err := h.createMonitoredItems(); err != nil {
		cancel()
		return nil, err
	}
	return h, nil
}

// interval is a tag's sampling interval: the request's, the subscription's otherwise.
func (h *SubscriptionHandle) interval(name string) time.Duration {
	if request, ok := h.subscriptionRequest.(interface{ GetInterval(string) time.Duration }); ok {
		if interval := request.GetInterval(name); interval > 0 {
			return interval
		}
	}
	if h.subscriptionType(name) == apiModel.SubscriptionCyclic {
		return h.cycleTime
	}
	return 0 // as fast as the server samples
}

func (h *SubscriptionHandle) subscriptionType(name string) apiModel.PlcSubscriptionType {
	if request, ok := h.subscriptionRequest.(interface {
		GetType(string) apiModel.PlcSubscriptionType
	}); ok {
		if t := request.GetType(name); t != 0 {
			return t
		}
	}
	return apiModel.SubscriptionChangeOfState
}

// createMonitoredItems creates a monitored item, reporting data changes of Value, per tag.
func (h *SubscriptionHandle) createMonitoredItems() error {
	channel := h.connection.channel
	requests := make([]readWriteModel.MonitoredItemCreateRequest, 0, len(h.tagNames))
	handles := make([]uint32, 0, len(h.tagNames))
	for i, name := range h.tagNames {
		tag, ok := h.subscriptionRequest.GetTag(name).(Tag)
		if !ok {
			return errors.Errorf("tag %s is not an OPC UA tag", name)
		}
		nodeId, err := generateNodeId(tag)
		if err != nil {
			return errors.Wrapf(err, "tag %s", name)
		}
		clientHandle := uint32(i + 1)
		h.clientHandles[clientHandle] = name
		handles = append(handles, clientHandle)
		requests = append(requests, readWriteModel.NewMonitoredItemCreateRequest(
			readWriteModel.NewReadValueId(nodeId, 0xD, NULL_STRING, readWriteModel.NewQualifiedName(0, NULL_STRING)),
			// Cyclic tags report too: Sampling would collect values without ever sending them.
			readWriteModel.MonitoringMode_monitoringModeReporting,
			readWriteModel.NewMonitoringParameters(clientHandle, float64(h.interval(name))/float64(time.Millisecond),
				NULL_EXTENSION_OBJECT, 1, true),
		))
	}
	ctx, cancel := context.WithTimeout(h.ctx, REQUEST_TIMEOUT_LONG*time.Millisecond)
	defer cancel()
	response, err := channel.call(ctx, h.connection.messageCodec, readWriteModel.NewCreateMonitoredItemsRequest(
		channel.newRequestHeader(channel.getRequestHandle()), h.subscriptionId,
		readWriteModel.TimestampsToReturn_timestampsToReturnBoth, requests))
	if err != nil {
		return errors.Wrap(err, "CreateMonitoredItems failed")
	}
	created, ok := response.(readWriteModel.CreateMonitoredItemsResponse)
	if !ok {
		return errors.Errorf("unexpected response %T to CreateMonitoredItems", response)
	}
	results := created.GetResults()
	for i, handle := range handles {
		name := h.clientHandles[handle]
		code := apiModel.PlcResponseCode_INTERNAL_ERROR
		if i < len(results) {
			code = responseCodeOf(results[i].GetStatusCode().GetStatusCode())
		}
		h.results[name] = code
		if code != apiModel.PlcResponseCode_OK {
			h.log.Warn().Str("tag", name).Stringer("code", code).Msg("tag left out of the subscription")
		}
	}
	return nil
}

// responseCodes are the codes of the tags: OK for those the subscription monitors.
func (h *SubscriptionHandle) responseCodes() map[string]apiModel.PlcResponseCode {
	h.mutex.Lock()
	defer h.mutex.Unlock()
	codes := make(map[string]apiModel.PlcResponseCode, len(h.results))
	for name, code := range h.results {
		codes[name] = code
	}
	return codes
}

// startSubscriber starts the Publish loops.
func (h *SubscriptionHandle) startSubscriber() {
	for range PUBLISH_REQUESTS {
		h.subscriberWg.Go(h.publishLoop)
	}
}

// publishLoop sends a Publish request, waits for its answer, delivers it and sends the next,
// until the subscription stops.
func (h *SubscriptionHandle) publishLoop() {
	channel := h.connection.channel
	// The server answers at the latest after keepAliveCount intervals; past twice that and a
	// margin the request is lost.
	wait := 2*time.Duration(h.keepAliveCount)*h.revisedCycleTime + REQUEST_TIMEOUT_LONG*time.Millisecond
	failures := 0
	for h.ctx.Err() == nil {
		h.mutex.Lock()
		acks := h.acks
		h.acks = nil
		h.mutex.Unlock()
		header := readWriteModel.NewRequestHeader(channel.getAuthenticationToken(), channel.getCurrentDateTime(),
			channel.getRequestHandle(), 0, NULL_STRING, uint32(wait/time.Millisecond), NULL_EXTENSION_OBJECT)
		ctx, cancel := context.WithTimeout(h.ctx, wait)
		response, err := channel.call(ctx, h.connection.messageCodec, readWriteModel.NewPublishRequest(header, acks))
		cancel()
		if h.ctx.Err() != nil {
			return
		}
		if err != nil {
			if !h.connection.messageCodec.IsRunning() {
				h.log.Warn().Err(err).Msg("subscription ended with the connection")
				h.plcSubscriber.subscriptionEnded(h)
				return
			}
			h.mutex.Lock()
			h.acks = append(acks, h.acks...) // acknowledge them with the next request
			h.mutex.Unlock()
			if status := faultStatus(err); status != 0 {
				switch status {
				case uint32(readWriteModel.OpcuaStatusCode_BadNoSubscription), uint32(readWriteModel.OpcuaStatusCode_BadSessionIdInvalid),
					uint32(readWriteModel.OpcuaStatusCode_BadSessionClosed), uint32(readWriteModel.OpcuaStatusCode_BadSubscriptionIdInvalid):
					h.log.Warn().Err(err).Msg("subscription ended by the server")
					h.plcSubscriber.subscriptionEnded(h)
					return
				case uint32(readWriteModel.OpcuaStatusCode_BadTooManyPublishRequests):
					// The server keeps fewer requests waiting: this loop waits a cycle.
				}
			}
			failures++
			h.log.Debug().Err(err).Int("failures", failures).Msg("Publish failed")
			select {
			case <-h.ctx.Done():
				return
			case <-time.After(min(time.Duration(failures)*h.revisedCycleTime, 10*time.Second)):
			}
			continue
		}
		failures = 0
		published, ok := response.(readWriteModel.PublishResponse)
		if !ok {
			h.log.Warn().Type("response", response).Msg("unexpected response to Publish")
			continue
		}
		h.onPublish(published)
	}
}

// onPublish acknowledges a notification message and delivers its data changes.
func (h *SubscriptionHandle) onPublish(response readWriteModel.PublishResponse) {
	message, ok := response.GetNotificationMessage().(readWriteModel.NotificationMessage)
	if !ok || len(message.GetNotificationData()) == 0 {
		return // a keep-alive
	}
	h.mutex.Lock()
	h.acks = append(h.acks, readWriteModel.NewSubscriptionAcknowledgement(response.GetSubscriptionId(), message.GetSequenceNumber()))
	h.mutex.Unlock()
	for _, data := range message.GetNotificationData() {
		switch notification := data.GetBody().(type) {
		case readWriteModel.DataChangeNotification:
			h.onSubscriptionValue(notification.GetMonitoredItems())
		case readWriteModel.StatusChangeNotification:
			h.log.Warn().Stringer("status", notification.GetStatus()).Msg("subscription status changed")
		default:
			h.log.Debug().Type("notification", notification).Msg("notification type not handled")
		}
	}
}

// onSubscriptionValue hands data changes to the consumers, an event per change so a tag that
// changed twice in one message reaches them twice, in order.
func (h *SubscriptionHandle) onSubscriptionValue(values []readWriteModel.MonitoredItemNotification) {
	for _, value := range values {
		name, ok := h.clientHandles[value.GetClientHandle()]
		if !ok {
			h.log.Debug().Uint32("clientHandle", value.GetClientHandle()).Msg("notification for an unknown monitored item")
			continue
		}
		_, responseCodes, responseValues := readResponse(h.log, nil, []string{name}, []readWriteModel.DataValue{value.GetValue()})
		tag := h.subscriptionRequest.GetTag(name)
		event := spiModel.NewDefaultPlcSubscriptionEvent(nil,
			map[string]apiModel.PlcTag{name: tag},
			map[string]apiModel.PlcSubscriptionType{name: h.subscriptionType(name)},
			map[string]time.Duration{name: h.interval(name)},
			responseCodes, responseValues)
		for _, consumer := range h.plcSubscriber.consumersOf(h) {
			consumer(event)
		}
	}
}

// stopSubscriber stops the Publish loops and deletes the subscription at the server.
func (h *SubscriptionHandle) stopSubscriber() {
	h.stopOnce.Do(func() {
		h.cancel()
		h.subscriberWg.Wait()
		channel := h.connection.channel
		if channel.authenticationToken == nil {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), REQUEST_TIMEOUT_LONG*time.Millisecond)
		defer cancel()
		if _, err := channel.call(ctx, h.connection.messageCodec, readWriteModel.NewDeleteSubscriptionsRequest(
			channel.newRequestHeader(channel.getRequestHandle()), []uint32{h.subscriptionId})); err != nil {
			h.log.Debug().Err(err).Msg("DeleteSubscriptions failed")
		}
	})
}
