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
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClientIdentityIsGeneratedOnceAndKept(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "certs")
	first, err := loadClientIdentity(zerolog.Nop(), directory, 2048, "urn:apache:plc4x:client")
	require.NoError(t, err)
	certificate, err := x509.ParseCertificate(first.certificate)
	require.NoError(t, err)
	require.Len(t, certificate.URIs, 1)
	assert.Equal(t, "urn:apache:plc4x:client", certificate.URIs[0].String(), "the application URI is in the certificate")
	assert.Equal(t, 2048, first.key.N.BitLen())

	second, err := loadClientIdentity(zerolog.Nop(), directory, 4096, "urn:apache:plc4x:client")
	require.NoError(t, err)
	assert.Equal(t, first.certificate, second.certificate, "the saved certificate is used again")
	assert.True(t, first.key.Equal(second.key))

	info, err := os.Stat(filepath.Join(directory, CLIENT_KEY_FILE))
	require.NoError(t, err)
	if os.PathSeparator == '/' {
		assert.Equal(t, os.FileMode(0o600), info.Mode().Perm(), "the key is readable by its owner only")
	}
}

func TestClientIdentityRefusesAKeyOfAnotherCertificate(t *testing.T) {
	directory := t.TempDir()
	_, err := loadClientIdentity(zerolog.Nop(), directory, 2048, "urn:test")
	require.NoError(t, err)
	other, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	der, err := x509.MarshalPKCS8PrivateKey(other)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(directory, CLIENT_KEY_FILE), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600))
	_, err = loadClientIdentity(zerolog.Nop(), directory, 2048, "urn:test")
	assert.ErrorContains(t, err, "does not belong")
}

func writeCertificate(t *testing.T, path string, certificates ...*x509.Certificate) {
	var data []byte
	for _, certificate := range certificates {
		data = append(data, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw})...)
	}
	require.NoError(t, os.WriteFile(path, data, 0o644))
}

// caSigned makes a CA and a server certificate it signs.
func caSigned(t *testing.T) (ca, server *x509.Certificate) {
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(10), Subject: pkix.Name{CommonName: "test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	require.NoError(t, err)
	ca, err = x509.ParseCertificate(caDER)
	require.NoError(t, err)
	serverKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	serverTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(11), Subject: pkix.Name{CommonName: "server"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature,
	}
	serverDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, ca, &serverKey.PublicKey, caKey)
	require.NoError(t, err)
	server, err = x509.ParseCertificate(serverDER)
	require.NoError(t, err)
	return ca, server
}

func TestServerTrust(t *testing.T) {
	directory := t.TempDir()
	server := identityForTest(t, "server", 2048).certificate
	stranger := identityForTest(t, "stranger", 2048).certificate
	ca, caSignedServer := caSigned(t)
	pinnedFile := filepath.Join(directory, "server.pem")
	writeCertificate(t, pinnedFile, server)
	trustDirectory := filepath.Join(directory, "trusted")
	require.NoError(t, os.Mkdir(trustDirectory, 0o700))
	writeCertificate(t, filepath.Join(trustDirectory, "server.crt"), server)
	require.NoError(t, os.WriteFile(filepath.Join(trustDirectory, "ca.der"), ca.Raw, 0o644))

	tests := []struct {
		name      string
		configure func(*Configuration)
		trusted   []*x509.Certificate
		refused   []*x509.Certificate
	}{
		{name: "nothing configured", configure: func(*Configuration) {}, refused: []*x509.Certificate{server, stranger}},
		{name: "verification off", configure: func(c *Configuration) { c.VerifyServerCertificate = false }, trusted: []*x509.Certificate{server, stranger}},
		{name: "pinned", configure: func(c *Configuration) { c.ServerCertificateFile = pinnedFile }, trusted: []*x509.Certificate{server}, refused: []*x509.Certificate{stranger, caSignedServer}},
		{name: "trust store", configure: func(c *Configuration) { c.TrustStore = trustDirectory }, trusted: []*x509.Certificate{server, caSignedServer}, refused: []*x509.Certificate{stranger}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			configuration := createDefaultConfiguration()
			tt.configure(&configuration)
			trust, err := newServerTrust(zerolog.Nop(), configuration)
			require.NoError(t, err)
			for _, certificate := range tt.trusted {
				assert.NoError(t, trust.verify([]*x509.Certificate{certificate}), certificate.Subject.CommonName)
			}
			for _, certificate := range tt.refused {
				assert.Error(t, trust.verify([]*x509.Certificate{certificate}), certificate.Subject.CommonName)
			}
		})
	}
}

func TestConfigurationReadsTheSecurityOptions(t *testing.T) {
	configuration, err := ParseFromOptions(zerolog.Nop(), map[string][]string{
		"security-policy":            {"Aes256_Sha256_RsaPss"},
		"message-security":           {"SIGN"},
		"generated-key-size":         {"4096"},
		"server-certificate-file":    {"/etc/server.pem"},
		"tls.trust-store":            {"/etc/trusted"},
		"tls.verify":                 {"false"},
		"allow-insecure-credentials": {"true"},
		"cert-directory":             {"/var/lib/plc4go"},
	})
	require.NoError(t, err)
	policy, err := configuration.securityPolicy()
	require.NoError(t, err)
	assert.Equal(t, "Aes256_Sha256_RsaPss", policy.name)
	mode, err := configuration.messageSecurityMode()
	require.NoError(t, err)
	assert.Equal(t, "messageSecurityModeSign", mode.String())
	assert.Equal(t, 4096, configuration.GeneratedKeySize)
	assert.Equal(t, "/etc/server.pem", configuration.ServerCertificateFile)
	assert.Equal(t, "/etc/trusted", configuration.TrustStore)
	assert.False(t, configuration.VerifyServerCertificate)
	assert.True(t, configuration.AllowInsecureCredentials)
	assert.Equal(t, "/var/lib/plc4go", configuration.CertDirectory)

	defaults, err := ParseFromOptions(zerolog.Nop(), map[string][]string{"security-policy": {"Basic256Sha256"}})
	require.NoError(t, err)
	mode, err = defaults.messageSecurityMode()
	require.NoError(t, err)
	assert.Equal(t, "messageSecurityModeSignAndEncrypt", mode.String(), "SIGN_ENCRYPT by default")
	assert.True(t, defaults.VerifyServerCertificate, "verifying by default")

	_, err = ParseFromOptions(zerolog.Nop(), map[string][]string{"security-policy": {"Basic512"}})
	assert.ErrorContains(t, err, "unknown security-policy")
	_, err = ParseFromOptions(zerolog.Nop(), map[string][]string{"security-policy": {"Basic256"}, "message-security": {"ENCRYPT"}})
	assert.ErrorContains(t, err, "unknown message-security")
}
