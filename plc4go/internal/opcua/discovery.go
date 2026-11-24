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

	"github.com/rs/zerolog"

	readWriteModel "github.com/apache/plc4x/plc4go/protocols/opcua/readwrite/model"
	"github.com/apache/plc4x/plc4go/spi/errors"
)

// discoverServerCertificate asks the server for its endpoints (GetEndpoints) over an unsecured
// channel on a connection of its own, and returns the certificate chain of the endpoint with
// the configured security policy and mode. The certificate is not trusted for having been
// discovered: the caller still has to verify it.
func discoverServerCertificate(ctx context.Context, log zerolog.Logger, configuration Configuration, codec *MessageCodec) ([]*x509.Certificate, error) {
	policy, err := configuration.securityPolicy()
	if err != nil {
		return nil, err
	}
	mode, err := configuration.messageSecurityMode()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, HANDSHAKE_TIMEOUT)
	defer cancel()
	if err := codec.Connect(ctx); err != nil {
		return nil, errors.Wrap(err, "error connecting for discovery")
	}
	defer func() {
		if err := codec.Disconnect(); err != nil {
			log.Debug().Err(err).Msg("error closing the discovery connection")
		}
	}()

	discoveryConfiguration := configuration
	discoveryConfiguration.SecurityPolicy = "None"
	discoveryConfiguration.Username, discoveryConfiguration.Password = "", ""
	channel := NewSecureChannel(log, DriverContext{}, discoveryConfiguration)
	channel.codec = codec
	if err := channel.hello(ctx, codec); err != nil {
		return nil, errors.Wrap(err, "discovery failed")
	}
	if err := channel.openChannel(ctx, codec, readWriteModel.SecurityTokenRequestType_securityTokenRequestTypeIssue); err != nil {
		return nil, errors.Wrap(err, "discovery failed")
	}
	response, err := channel.call(ctx, codec, readWriteModel.NewGetEndpointsRequest(channel.newRequestHeader(channel.getRequestHandle()), channel.endpoint, nil, nil))
	if closeErr := channel.closeChannel(ctx, codec); closeErr != nil {
		log.Debug().Err(closeErr).Msg("error closing the discovery channel")
	}
	if err != nil {
		return nil, errors.Wrap(err, "GetEndpoints failed")
	}
	endpoints, ok := response.(readWriteModel.GetEndpointsResponse)
	if !ok {
		return nil, errors.Errorf("unexpected response %T to GetEndpoints", response)
	}
	endpoint := selectEndpoint(endpoints.GetEndpoints(), policy, mode, configuration.Endpoint)
	if endpoint == nil {
		return nil, errors.Errorf("server has no endpoint with security policy %s and message security %s", policy.name, mode)
	}
	var raw []byte
	if certificate := endpoint.GetServerCertificate(); certificate != nil {
		raw = certificate.GetStringValue()
	}
	chain, err := x509.ParseCertificates(raw)
	if err != nil || len(chain) == 0 {
		return nil, errors.Wrap(err, "error parsing the certificate of the server's endpoint")
	}
	log.Debug().Str("subject", chain[0].Subject.String()).Msg("discovered the server certificate")
	return chain, nil
}

// selectEndpoint picks the endpoint with the security policy and mode, preferring the one at
// the URL the client connects to: servers often list one endpoint per host name they have.
func selectEndpoint(endpoints []readWriteModel.EndpointDescription, policy *securityPolicy, mode readWriteModel.MessageSecurityMode, url string) readWriteModel.EndpointDescription {
	var found readWriteModel.EndpointDescription
	for _, endpoint := range endpoints {
		uri := endpoint.GetSecurityPolicyUri()
		if uri == nil || uri.GetStringValue() == nil || *uri.GetStringValue() != policy.uri || endpoint.GetSecurityMode() != mode {
			continue
		}
		if endpointUrl := endpoint.GetEndpointUrl(); endpointUrl != nil && endpointUrl.GetStringValue() != nil && *endpointUrl.GetStringValue() == url {
			return endpoint
		}
		if found == nil {
			found = endpoint
		}
	}
	return found
}
