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
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"hash"
	"strings"

	"github.com/apache/plc4x/plc4go/spi/errors"
)

// cryptoRandRead fills nonces; a variable so tests can make them predictable.
var cryptoRandRead = rand.Read

// SECURITY_POLICY_URI_PREFIX starts every security policy URI.
const SECURITY_POLICY_URI_PREFIX = "http://opcfoundation.org/UA/SecurityPolicy#"

// asymmetricSignature names an RSA signature scheme of a security policy.
type asymmetricSignature int

const (
	rsaPkcs15Sha1 asymmetricSignature = iota
	rsaPkcs15Sha256
	rsaPssSha256
)

// asymmetricEncryption names an RSA encryption scheme of a security policy.
type asymmetricEncryption int

const (
	rsaPkcs15 asymmetricEncryption = iota
	rsaOaepSha1
	rsaOaepSha256
)

// securityPolicy holds the algorithms and sizes of an OPC UA security policy (OPC UA Part 7).
// The asymmetric algorithms secure OpenSecureChannel messages and the session handshake; the
// symmetric ones, keyed from both sides' nonces, secure every other message.
type securityPolicy struct {
	name string
	uri  string

	asymmetricSignature  asymmetricSignature
	asymmetricEncryption asymmetricEncryption
	// symmetricHash is the hash of the HMAC that signs messages and of the P_hash that derives keys.
	symmetricHash func() hash.Hash
	// signatureKeyLength, encryptionKeyLength and the AES block size are the parts of the
	// derived key material, in this order.
	signatureKeyLength  int
	encryptionKeyLength int
	nonceLength         int
}

// SECURITY_POLICY_NONE_URI is the URI of the policy without security.
const SECURITY_POLICY_NONE_URI = SECURITY_POLICY_URI_PREFIX + "None"

var securityPolicies = []*securityPolicy{
	{name: "None", uri: SECURITY_POLICY_NONE_URI},
	{
		name: "Basic128Rsa15", uri: SECURITY_POLICY_URI_PREFIX + "Basic128Rsa15",
		asymmetricSignature: rsaPkcs15Sha1, asymmetricEncryption: rsaPkcs15, symmetricHash: sha1.New,
		signatureKeyLength: 16, encryptionKeyLength: 16, nonceLength: 16,
	},
	{
		name: "Basic256", uri: SECURITY_POLICY_URI_PREFIX + "Basic256",
		asymmetricSignature: rsaPkcs15Sha1, asymmetricEncryption: rsaOaepSha1, symmetricHash: sha1.New,
		signatureKeyLength: 24, encryptionKeyLength: 32, nonceLength: 32,
	},
	{
		name: "Basic256Sha256", uri: SECURITY_POLICY_URI_PREFIX + "Basic256Sha256",
		asymmetricSignature: rsaPkcs15Sha256, asymmetricEncryption: rsaOaepSha1, symmetricHash: sha256.New,
		signatureKeyLength: 32, encryptionKeyLength: 32, nonceLength: 32,
	},
	{
		name: "Aes128_Sha256_RsaOaep", uri: SECURITY_POLICY_URI_PREFIX + "Aes128_Sha256_RsaOaep",
		asymmetricSignature: rsaPkcs15Sha256, asymmetricEncryption: rsaOaepSha1, symmetricHash: sha256.New,
		signatureKeyLength: 32, encryptionKeyLength: 16, nonceLength: 32,
	},
	{
		name: "Aes256_Sha256_RsaPss", uri: SECURITY_POLICY_URI_PREFIX + "Aes256_Sha256_RsaPss",
		asymmetricSignature: rsaPssSha256, asymmetricEncryption: rsaOaepSha256, symmetricHash: sha256.New,
		signatureKeyLength: 32, encryptionKeyLength: 32, nonceLength: 32,
	},
}

// securityPolicyByName finds a policy by its name ("Basic256Sha256"), ignoring case, or by its URI.
func securityPolicyByName(name string) (*securityPolicy, error) {
	if name == "" {
		name = "None"
	}
	for _, policy := range securityPolicies {
		if strings.EqualFold(policy.name, name) || policy.uri == name {
			return policy, nil
		}
	}
	names := make([]string, len(securityPolicies))
	for i, policy := range securityPolicies {
		names[i] = policy.name
	}
	return nil, errors.Errorf("unknown security-policy %q: use one of %s", name, strings.Join(names, ", "))
}

// isNone reports whether the policy is None: no signatures, no encryption.
func (p *securityPolicy) isNone() bool {
	return p.symmetricHash == nil
}

// symmetricSignatureSize is the size of the HMAC that signs a symmetric chunk.
func (p *securityPolicy) symmetricSignatureSize() int {
	if p.isNone() {
		return 0
	}
	return p.symmetricHash().Size()
}

// symmetricBlockSize is the AES block size.
func (p *securityPolicy) symmetricBlockSize() int {
	if p.isNone() {
		return 1
	}
	return aes.BlockSize
}

// asymmetricSignatureURI names the policy's RSA signature scheme in a SignatureData.
func (p *securityPolicy) asymmetricSignatureURI() string {
	switch p.asymmetricSignature {
	case rsaPkcs15Sha1:
		return "http://www.w3.org/2000/09/xmldsig#rsa-sha1"
	case rsaPssSha256:
		return "http://opcfoundation.org/UA/security/rsa-pss-sha2-256"
	default:
		return "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
	}
}

// asymmetricEncryptionURI names the policy's RSA encryption scheme in a user identity token.
func (p *securityPolicy) asymmetricEncryptionURI() string {
	switch p.asymmetricEncryption {
	case rsaPkcs15:
		return "http://www.w3.org/2001/04/xmlenc#rsa-1_5"
	case rsaOaepSha256:
		return "http://opcfoundation.org/UA/security/rsa-oaep-sha2-256"
	default:
		return "http://www.w3.org/2001/04/xmlenc#rsa-oaep"
	}
}

// digest hashes data with the hash of the policy's RSA signature scheme.
func (p *securityPolicy) digest(data []byte) (crypto.Hash, []byte) {
	if p.asymmetricSignature == rsaPkcs15Sha1 {
		sum := sha1.Sum(data)
		return crypto.SHA1, sum[:]
	}
	sum := sha256.Sum256(data)
	return crypto.SHA256, sum[:]
}

// asymmetricSign signs data with the policy's RSA signature scheme.
func (p *securityPolicy) asymmetricSign(key *rsa.PrivateKey, data []byte) ([]byte, error) {
	hashFunction, digest := p.digest(data)
	if p.asymmetricSignature == rsaPssSha256 {
		return rsa.SignPSS(rand.Reader, key, hashFunction, digest, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
	}
	return rsa.SignPKCS1v15(rand.Reader, key, hashFunction, digest)
}

// asymmetricVerify checks a signature made with the policy's RSA signature scheme.
func (p *securityPolicy) asymmetricVerify(key *rsa.PublicKey, data, signature []byte) error {
	hashFunction, digest := p.digest(data)
	if p.asymmetricSignature == rsaPssSha256 {
		return rsa.VerifyPSS(key, hashFunction, digest, signature, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
	}
	return rsa.VerifyPKCS1v15(key, hashFunction, digest, signature)
}

// asymmetricPlainTextBlockSize is how many bytes of plain text one RSA block of key carries.
func (p *securityPolicy) asymmetricPlainTextBlockSize(key *rsa.PublicKey) int {
	switch p.asymmetricEncryption {
	case rsaPkcs15:
		return key.Size() - 11
	case rsaOaepSha256:
		return key.Size() - 2*sha256.Size - 2
	default:
		return key.Size() - 2*sha1.Size - 2
	}
}

// asymmetricEncrypt encrypts one block of plain text for key.
func (p *securityPolicy) asymmetricEncrypt(key *rsa.PublicKey, block []byte) ([]byte, error) {
	switch p.asymmetricEncryption {
	case rsaPkcs15:
		return rsa.EncryptPKCS1v15(rand.Reader, key, block)
	case rsaOaepSha256:
		return rsa.EncryptOAEP(sha256.New(), rand.Reader, key, block, nil)
	default:
		return rsa.EncryptOAEP(sha1.New(), rand.Reader, key, block, nil)
	}
}

// asymmetricDecrypt decrypts one block of cipher text with key.
func (p *securityPolicy) asymmetricDecrypt(key *rsa.PrivateKey, block []byte) ([]byte, error) {
	switch p.asymmetricEncryption {
	case rsaPkcs15:
		return rsa.DecryptPKCS1v15(nil, key, block)
	case rsaOaepSha256:
		return rsa.DecryptOAEP(sha256.New(), nil, key, block, nil)
	default:
		return rsa.DecryptOAEP(sha1.New(), nil, key, block, nil)
	}
}

// asymmetricEncryptAll encrypts plainText for key, block by block.
func (p *securityPolicy) asymmetricEncryptAll(key *rsa.PublicKey, plainText []byte) ([]byte, error) {
	blockSize := p.asymmetricPlainTextBlockSize(key)
	cipherText := make([]byte, 0, (len(plainText)+blockSize-1)/blockSize*key.Size())
	for start := 0; start < len(plainText); start += blockSize {
		block, err := p.asymmetricEncrypt(key, plainText[start:min(start+blockSize, len(plainText))])
		if err != nil {
			return nil, errors.Wrap(err, "error encrypting")
		}
		cipherText = append(cipherText, block...)
	}
	return cipherText, nil
}

// keySet is one side's key material of a secure channel token (OPC UA Part 6, 6.7.5).
type keySet struct {
	signingKey    []byte
	encryptingKey []byte
	iv            []byte
}

// deriveKeys derives one side's keys. The keys a side secures its messages with come from
// P_hash(secret = the other side's nonce, seed = its own nonce).
func (p *securityPolicy) deriveKeys(secret, seed []byte) keySet {
	length := p.signatureKeyLength + p.encryptionKeyLength + aes.BlockSize
	material := pHash(p.symmetricHash, secret, seed, length)
	return keySet{
		signingKey:    material[:p.signatureKeyLength],
		encryptingKey: material[p.signatureKeyLength : p.signatureKeyLength+p.encryptionKeyLength],
		iv:            material[p.signatureKeyLength+p.encryptionKeyLength:],
	}
}

// pHash is the TLS P_hash function (RFC 5246, section 5) OPC UA derives its keys with.
func pHash(hashFunction func() hash.Hash, secret, seed []byte, length int) []byte {
	result := make([]byte, 0, length)
	mac := hmac.New(hashFunction, secret)
	mac.Write(seed)
	a := mac.Sum(nil) // A(1)
	for len(result) < length {
		mac.Reset()
		mac.Write(a)
		mac.Write(seed)
		result = mac.Sum(result)
		mac.Reset()
		mac.Write(a)
		a = mac.Sum(nil)
	}
	return result[:length]
}

// symmetricSign signs data with the HMAC of the policy.
func (p *securityPolicy) symmetricSign(keys keySet, data []byte) []byte {
	mac := hmac.New(p.symmetricHash, keys.signingKey)
	mac.Write(data)
	return mac.Sum(nil)
}

// symmetricVerify checks an HMAC signature in constant time.
func (p *securityPolicy) symmetricVerify(keys keySet, data, signature []byte) error {
	if subtle.ConstantTimeCompare(p.symmetricSign(keys, data), signature) != 1 {
		return errors.New("message signature does not verify")
	}
	return nil
}

// symmetricCrypt encrypts or decrypts data in place with AES-CBC. len(data) must be a
// multiple of the AES block size.
func (p *securityPolicy) symmetricCrypt(keys keySet, data []byte, encrypt bool) error {
	if len(data)%aes.BlockSize != 0 {
		return errors.Errorf("%d bytes are not a whole number of AES blocks", len(data))
	}
	block, err := aes.NewCipher(keys.encryptingKey)
	if err != nil {
		return errors.Wrap(err, "error creating cipher")
	}
	if encrypt {
		cipher.NewCBCEncrypter(block, keys.iv).CryptBlocks(data, data)
	} else {
		cipher.NewCBCDecrypter(block, keys.iv).CryptBlocks(data, data)
	}
	return nil
}
