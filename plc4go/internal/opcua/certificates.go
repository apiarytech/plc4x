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
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/rs/zerolog"

	"github.com/apache/plc4x/plc4go/spi/errors"
)

// Names of the client's certificate and key in the cert-directory.
const (
	CLIENT_CERTIFICATE_FILE = "plc4go-opcua-client.pem"
	CLIENT_KEY_FILE         = "plc4go-opcua-client-key.pem"
)

// clientIdentity is the certificate and key the driver signs, and is encrypted for, with.
type clientIdentity struct {
	key         *rsa.PrivateKey
	certificate []byte // DER
}

// loadClientIdentity reads the client's certificate and key from directory, generating and
// saving them there the first time. Without a directory it generates a certificate for this
// connection only, which a server that keeps a trust list has to be told to trust again on
// every connection.
func loadClientIdentity(log zerolog.Logger, directory string, keySize int, applicationUri string) (clientIdentity, error) {
	if keySize == 0 {
		keySize = 2048
	}
	if directory == "" {
		log.Warn().Msg("no cert-directory configured: using a certificate generated for this connection only")
		return generateClientIdentity(keySize, applicationUri)
	}
	certificateFile := filepath.Join(directory, CLIENT_CERTIFICATE_FILE)
	keyFile := filepath.Join(directory, CLIENT_KEY_FILE)
	certificatePEM, certificateErr := os.ReadFile(certificateFile)
	keyPEM, keyErr := os.ReadFile(keyFile)
	if os.IsNotExist(certificateErr) && os.IsNotExist(keyErr) {
		identity, err := generateClientIdentity(keySize, applicationUri)
		if err != nil {
			return clientIdentity{}, err
		}
		if err := saveClientIdentity(directory, identity); err != nil {
			return clientIdentity{}, err
		}
		log.Info().Str("certificate", certificateFile).Msg("generated the client certificate; the server has to trust it")
		return identity, nil
	}
	if certificateErr != nil {
		return clientIdentity{}, errors.Wrapf(certificateErr, "error reading %s", certificateFile)
	}
	if keyErr != nil {
		return clientIdentity{}, errors.Wrapf(keyErr, "error reading %s", keyFile)
	}
	certificates, err := parseCertificates(certificatePEM)
	if err != nil || len(certificates) == 0 {
		return clientIdentity{}, errors.Wrapf(err, "no certificate in %s", certificateFile)
	}
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return clientIdentity{}, errors.Errorf("no PEM key in %s", keyFile)
	}
	var key *rsa.PrivateKey
	if parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		rsaKey, ok := parsed.(*rsa.PrivateKey)
		if !ok {
			return clientIdentity{}, errors.Errorf("key in %s is %T, the security policies need RSA", keyFile, parsed)
		}
		key = rsaKey
	} else if key, err = x509.ParsePKCS1PrivateKey(block.Bytes); err != nil {
		return clientIdentity{}, errors.Wrapf(err, "error parsing the key in %s", keyFile)
	}
	if !key.PublicKey.Equal(certificates[0].PublicKey) {
		return clientIdentity{}, errors.Errorf("the key in %s does not belong to the certificate in %s", keyFile, certificateFile)
	}
	return clientIdentity{key: key, certificate: certificates[0].Raw}, nil
}

// generateClientIdentity makes a self-signed application instance certificate (OPC UA Part 6,
// 6.2.2): its subject alternative name carries the application URI the client announces.
func generateClientIdentity(keySize int, applicationUri string) (clientIdentity, error) {
	key, err := rsa.GenerateKey(rand.Reader, keySize)
	if err != nil {
		return clientIdentity{}, errors.Wrap(err, "error generating key")
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 63))
	if err != nil {
		return clientIdentity{}, errors.Wrap(err, "error generating serial number")
	}
	uri, err := url.Parse(applicationUri)
	if err != nil {
		return clientIdentity{}, errors.Wrap(err, "error parsing application URI")
	}
	hostname, _ := os.Hostname()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "Apache PLC4X OPC UA client",
			Organization: []string{"Apache Software Foundation"},
		},
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().AddDate(5, 0, 0),
		URIs:      []*url.URL{uri},
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment | x509.KeyUsageKeyEncipherment |
			x509.KeyUsageDataEncipherment | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	if hostname != "" {
		template.DNSNames = []string{hostname}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return clientIdentity{}, errors.Wrap(err, "error creating certificate")
	}
	return clientIdentity{key: key, certificate: der}, nil
}

func saveClientIdentity(directory string, identity clientIdentity) error {
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return errors.Wrapf(err, "error creating %s", directory)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(identity.key)
	if err != nil {
		return errors.Wrap(err, "error encoding key")
	}
	keyFile := filepath.Join(directory, CLIENT_KEY_FILE)
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		return errors.Wrapf(err, "error writing %s", keyFile)
	}
	certificateFile := filepath.Join(directory, CLIENT_CERTIFICATE_FILE)
	if err := os.WriteFile(certificateFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: identity.certificate}), 0o644); err != nil {
		return errors.Wrapf(err, "error writing %s", certificateFile)
	}
	return nil
}

// parseCertificates reads certificates in PEM, or one certificate (or chain) in DER.
func parseCertificates(data []byte) ([]*x509.Certificate, error) {
	if !bytes.Contains(data, []byte("-----BEGIN")) {
		return x509.ParseCertificates(data)
	}
	var certificates []*x509.Certificate
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, errors.Wrap(err, "error parsing certificate")
		}
		certificates = append(certificates, certificate)
	}
	return certificates, nil
}

// readCertificates reads the certificates of a file, or of every .pem, .crt, .cer and .der file
// of a directory.
func readCertificates(path string) ([]*x509.Certificate, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	files := []string{path}
	if info.IsDir() {
		entries, err := os.ReadDir(path)
		if err != nil {
			return nil, err
		}
		files = files[:0]
		for _, entry := range entries {
			switch strings.ToLower(filepath.Ext(entry.Name())) {
			case ".pem", ".crt", ".cer", ".der":
				if !entry.IsDir() {
					files = append(files, filepath.Join(path, entry.Name()))
				}
			}
		}
	}
	var certificates []*x509.Certificate
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			return nil, err
		}
		parsed, err := parseCertificates(data)
		if err != nil {
			return nil, errors.Wrapf(err, "error reading %s", file)
		}
		certificates = append(certificates, parsed...)
	}
	if len(certificates) == 0 {
		return nil, errors.Errorf("no certificate in %s", path)
	}
	return certificates, nil
}

// certificateVerifier decides whether to trust a server's certificate chain (leaf first).
type certificateVerifier func(chain []*x509.Certificate) error

// serverTrust is what the configuration says about the server's certificate: how to verify
// it, and the certificate itself when it is pinned.
type serverTrust struct {
	verify certificateVerifier
	pinned *x509.Certificate
}

// newServerTrust builds the server certificate check of a configuration, as PLC4J does:
// tls.verify=false trusts any certificate, a trust store checks the chain, a pinned
// server-certificate-file must match exactly, and with none of these every certificate is
// refused.
func newServerTrust(log zerolog.Logger, configuration Configuration) (serverTrust, error) {
	var trust serverTrust
	if configuration.ServerCertificateFile != "" {
		certificates, err := readCertificates(configuration.ServerCertificateFile)
		if err != nil {
			return trust, errors.Wrap(err, "error reading server-certificate-file")
		}
		trust.pinned = certificates[0]
	}
	switch {
	case !configuration.VerifyServerCertificate:
		trust.verify = func([]*x509.Certificate) error { return nil }
	case configuration.TrustStore != "":
		trusted, err := readCertificates(configuration.TrustStore)
		if err != nil {
			return trust, errors.Wrap(err, "error reading tls.trust-store")
		}
		trust.verify = func(chain []*x509.Certificate) error { return verifyChain(chain, trusted) }
	case trust.pinned != nil:
		log.Info().Str("file", configuration.ServerCertificateFile).Msg("pinning the server certificate")
		pinned := trust.pinned
		trust.verify = func(chain []*x509.Certificate) error {
			if len(chain) == 0 || !bytes.Equal(chain[0].Raw, pinned.Raw) {
				return errors.New("server certificate does not match the pinned server-certificate-file")
			}
			return nil
		}
	default:
		trust.verify = func([]*x509.Certificate) error {
			return errors.New("no trust anchor for the server certificate: name it with server-certificate-file, " +
				"or the certificates to trust with tls.trust-store, or set tls.verify=false for tests only")
		}
	}
	return trust, nil
}

// verifyChain trusts a chain whose leaf is one of the trusted certificates (as a self-signed
// application certificate usually is) or that chains to one of them.
func verifyChain(chain []*x509.Certificate, trusted []*x509.Certificate) error {
	if len(chain) == 0 {
		return errors.New("no server certificate")
	}
	leaf := chain[0]
	roots := x509.NewCertPool()
	for _, certificate := range trusted {
		if bytes.Equal(certificate.Raw, leaf.Raw) {
			if time.Now().After(leaf.NotAfter) || time.Now().Before(leaf.NotBefore) {
				return errors.Errorf("server certificate is valid from %s to %s", leaf.NotBefore, leaf.NotAfter)
			}
			return nil
		}
		roots.AddCert(certificate)
	}
	intermediates := x509.NewCertPool()
	for _, certificate := range chain[1:] {
		intermediates.AddCert(certificate)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		return errors.Wrap(err, "server certificate is not trusted")
	}
	return nil
}
