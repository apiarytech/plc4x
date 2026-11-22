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
	"reflect"
	"strconv"
	"strings"

	"github.com/rs/zerolog"

	readWriteModel "github.com/apache/plc4x/plc4go/protocols/opcua/readwrite/model"
	"github.com/apache/plc4x/plc4go/spi/errors"
	spiOptions "github.com/apache/plc4x/plc4go/spi/options"
)

//go:generate go tool plc4xGenerator -type=Configuration
type Configuration struct {
	Code              string
	Host              string
	Port              string
	Endpoint          string
	TransportEndpoint string
	Params            string
	Discovery         bool
	Username          string
	// The credentials below render as <redacted>, never as their values - see the generator's
	// secret tag. Username is not marked: it says who is connecting, which is a diagnostic.
	Password       string `secret:"true"`
	SecurityPolicy string
	// MessageSecurity is SIGN or SIGN_ENCRYPT: what a channel with a security policy other than
	// None does to the messages after the handshake.
	MessageSecurity string
	// KeyStoreFile and KeyStorePassword name a PKCS#12 key store, as PLC4J reads one. This binding
	// does not read PKCS#12; it takes its certificate from CertDirectory instead.
	KeyStoreFile     string
	KeyStorePassword string `secret:"true"`
	// CertDirectory holds the client's certificate and key as PEM files. They are generated
	// there on first use, so the server can be told to trust one certificate for good.
	CertDirectory    string
	GeneratedKeySize int
	// ServerCertificateFile pins the server's certificate (DER or PEM); TrustStore names PEM or
	// DER certificates, a file or a directory, that a server's certificate must chain to.
	// VerifyServerCertificate false trusts any server certificate: for tests only.
	ServerCertificateFile   string
	TrustStore              string
	VerifyServerCertificate bool
	// AllowInsecureCredentials allows a password to be sent where nothing encrypts it.
	AllowInsecureCredentials bool
	// Bounds of a browse, as in PLC4J: references collected per node, nodes expanded per query,
	// and depth of the tree. 0 means no bound.
	BrowseMaxReferencesPerNode int
	BrowseMaxTotalNodes        int
	BrowseMaxDepth             int
	// AllowUnverifiedSecurityPolicies was the opt-in for security policies before the driver
	// verified certificates and signatures. It is read so old connection strings still parse,
	// and has no effect.
	AllowUnverifiedSecurityPolicies bool

	log zerolog.Logger
}

// fieldForOption maps a connection-string option to the Configuration field it sets.
//
// The names are the ones PLC4J declares and the documentation lists, not this struct's Go field
// names. Deriving them from the field names is what made this driver read "keyStoreFile" and
// "keyStorePassword": the documented "tls.keystore" and "tls.keystore-password" reached it as
// unknown options and were ignored, so the two bindings disagreed about the same string.
//
// Keys are lower-case; lookup lower-cases the option, which keeps the case-insensitive matching
// this driver has always had.
var fieldForOption = map[string]string{
	"discovery":                      "Discovery",
	"username":                       "Username",
	"password":                       "Password",
	"security-policy":                "SecurityPolicy",
	"message-security":               "MessageSecurity",
	"tls.keystore":                   "KeyStoreFile",
	"tls.keystore-password":          "KeyStorePassword",
	"generated-key-size":             "GeneratedKeySize",
	"server-certificate-file":        "ServerCertificateFile",
	"tls.trust-store":                "TrustStore",
	"tls.verify":                     "VerifyServerCertificate",
	"allow-insecure-credentials":     "AllowInsecureCredentials",
	"browse-max-references-per-node": "BrowseMaxReferencesPerNode",
	"browse-max-total-nodes":         "BrowseMaxTotalNodes",
	"browse-max-depth":               "BrowseMaxDepth",
	// No PLC4J counterpart: this binding keeps its certificate in a directory rather than
	// taking a key store, so the name is this binding's own - in the shared spelling.
	"cert-directory":                     "CertDirectory",
	"allow-unverified-security-policies": "AllowUnverifiedSecurityPolicies",
}

func ParseFromOptions(log zerolog.Logger, options map[string][]string) (Configuration, error) {
	configuration := createDefaultConfiguration()
	reflectConfiguration := reflect.ValueOf(&configuration).Elem()
	for optionKey := range options {
		fieldName, ok := fieldForOption[strings.ToLower(optionKey)]
		if !ok {
			// The driver manager's bookkeeping, not a user option.
			if optionKey == spiOptions.ActiveTransportOption {
				continue
			}
			// Read by the transport rather than by this driver. The names come from the
			// transports themselves, which register what they read, so this driver does not
			// keep its own copy of a list that would drift from them.
			if spiOptions.IsTransportOption(optionKey) {
				continue
			}
			// Warn rather than fail, matching plc4j, which reports an unknown parameter and
			// carries on for every driver. This driver used to be the only one anywhere in
			// PLC4X that refused the connection, which meant one connection string was
			// accepted by plc4j and rejected here.
			//
			// The reason it refused is still real and is now carried by the warning instead:
			// a typo in a security-relevant option (securityPolicy, allowUnverified...) falls
			// back to a default, and the operator has to see that it did. An unread option is
			// reported by name, so it is visible - but it no longer stops the connection.
			log.Warn().
				Str("option", optionKey).
				Msg("Connection string option is not known to the opcua driver and is ignored")
			continue
		}
		optionValue := getFromOptions(log, options, optionKey)
		if optionValue == "" {
			continue
		}
		field := reflectConfiguration.FieldByName(fieldName)
		switch field.Kind() {
		case reflect.String:
			field.SetString(optionValue)
		case reflect.Int:
			parseInt, err := strconv.ParseInt(optionValue, 0, 32)
			if err != nil {
				return Configuration{}, errors.Wrapf(err, "Error parsing %s", optionKey)
			}
			field.SetInt(parseInt)
		case reflect.Uint8:
			parseUint, err := strconv.ParseUint(optionValue, 0, 8)
			if err != nil {
				return Configuration{}, errors.Wrapf(err, "Error parsing %s", optionKey)
			}
			field.SetUint(parseUint)
		case reflect.Bool:
			parseBool, err := strconv.ParseBool(optionValue)
			if err != nil {
				return Configuration{}, errors.Wrapf(err, "Error parsing %s", optionKey)
			}
			field.SetBool(parseBool)
		default:
			return Configuration{}, errors.Errorf("%s not yet supported", field.Kind())
		}
	}
	configuration.log = log
	if err := configuration.validateSecurityPolicy(); err != nil {
		return Configuration{}, err
	}
	return configuration, nil
}

// validateSecurityPolicy checks the security options name things the driver knows.
func (c *Configuration) validateSecurityPolicy() error {
	policy, err := c.securityPolicy()
	if err != nil {
		return err
	}
	if _, err := c.messageSecurityMode(); err != nil {
		return err
	}
	if c.AllowUnverifiedSecurityPolicies {
		c.log.Warn().Msg("allow-unverified-security-policies no longer has an effect: the driver verifies server certificates and message signatures")
	}
	if !policy.isNone() && !c.VerifyServerCertificate {
		c.log.Warn().Msg("tls.verify=false: the server's certificate is not verified. The connection is open to man-in-the-middle attacks; use this for tests only")
	}
	return nil
}

// securityPolicy is the security policy the configuration asks for.
func (c *Configuration) securityPolicy() (*securityPolicy, error) {
	return securityPolicyByName(c.SecurityPolicy)
}

// messageSecurityMode is the message security mode the configuration asks for: None for the
// None policy, Sign or SignAndEncrypt otherwise.
func (c *Configuration) messageSecurityMode() (readWriteModel.MessageSecurityMode, error) {
	policy, err := c.securityPolicy()
	if err != nil {
		return 0, err
	}
	if policy.isNone() {
		return readWriteModel.MessageSecurityMode_messageSecurityModeNone, nil
	}
	switch strings.ToUpper(strings.ReplaceAll(c.MessageSecurity, "-", "_")) {
	case "SIGN":
		return readWriteModel.MessageSecurityMode_messageSecurityModeSign, nil
	case "", "SIGN_ENCRYPT", "SIGNANDENCRYPT", "SIGN_AND_ENCRYPT":
		return readWriteModel.MessageSecurityMode_messageSecurityModeSignAndEncrypt, nil
	default:
		return 0, errors.Errorf("unknown message-security %q: use SIGN or SIGN_ENCRYPT", c.MessageSecurity)
	}
}

func createDefaultConfiguration() Configuration {
	return Configuration{
		SecurityPolicy:             "None",
		MessageSecurity:            "SIGN_ENCRYPT",
		GeneratedKeySize:           2048,
		VerifyServerCertificate:    true,
		Discovery:                  true,
		BrowseMaxReferencesPerNode: 65536,
		BrowseMaxTotalNodes:        1000000,
		BrowseMaxDepth:             64,
	}
}

func getFromOptions(localLog zerolog.Logger, options map[string][]string, key string) string {
	if optionValues, ok := options[key]; ok {
		if len(optionValues) <= 0 {
			return ""
		}
		if len(optionValues) > 1 {
			localLog.Warn().Str("key", key).Msg("Options must be unique")
		}
		return optionValues[0]
	}
	return ""
}
