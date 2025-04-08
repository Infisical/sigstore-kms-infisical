//
// Copyright 2021 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package infisical2 implement the interface with infisical kms service
package infisical2

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"os"
	"regexp"
	"strings"
	"time"

	infisical "github.com/infisical/go-sdk"
	"github.com/jellydator/ttlcache/v3"
)

type infisicalClient struct {
	client    infisical.InfisicalClientInterface
	keyName   string
	projectId string
	keyCache  *ttlcache.Cache[string, crypto.PublicKey]
}

var (
	errReference   = errors.New("kms specification should be in the format infisicalkms://<key-name>")
	referenceRegex = regexp.MustCompile(`^infisicalkms://([^/]+)$`)
)

const (
	// use a consistent key for cache lookups
	cacheKey = "infisical-signer"

	// ReferenceScheme schemes for various KMS services are copied from https://github.com/google/go-cloud/tree/master/secrets
	ReferenceScheme = "infisicalkms://"
)

// ValidReference returns a non-nil error if the reference string is invalid
func ValidReference(ref string) error {
	if !referenceRegex.MatchString(ref) {
		return errReference
	}
	return nil
}

func parseReference(resourceID string) (keyName string, err error) {
	v := referenceRegex.FindStringSubmatch(resourceID)
	if len(v) < 1 {
		err = fmt.Errorf("invalid infisical format %q: %w", resourceID, err)
		return
	}
	keyName = v[1]
	return
}

func newInfisicalClient(keyResourceID string) (*infisicalClient, error) {
	if err := ValidReference(keyResourceID); err != nil {
		return nil, err
	}

	keyName, err := parseReference(keyResourceID)
	if err != nil {
		return nil, err
	}

	siteUrl := os.Getenv("INFISICAL_SITE_URL")
	if siteUrl == "" {
		siteUrl = "https://app.infisical.com"
	}

	universalClientId := os.Getenv("INFISICAL_UNIVERSAL_CLIENT_ID")
	universalClientSecret := os.Getenv("INFISICAL_UNIVERSAL_CLIENT_SECRET")
	projectId := os.Getenv("INFISICAL_PROJECT_ID")
	if universalClientId == "" || universalClientSecret == "" {
		return nil, errors.New("INFISICAL_UNIVERSAL_CLIENT_ID and INFISICAL_UNIVERSAL_CLIENT_SECRET are not set in the environment")
	}

	if projectId == "" {
		return nil, errors.New("INFISICAL_PROJECT_ID is not set in the environment")
	}

	client := infisical.NewInfisicalClient(context.Background(), infisical.Config{
		SiteUrl: siteUrl,
	})

	_, err = client.Auth().UniversalAuthLogin(universalClientId, universalClientSecret)

	if err != nil {
		return nil, fmt.Errorf("universal auth login: %w", err)
	}

	infisicalClient := &infisicalClient{
		client:    client,
		keyName:   keyName,
		projectId: projectId,
		keyCache: ttlcache.New[string, crypto.PublicKey](
			ttlcache.WithDisableTouchOnHit[string, crypto.PublicKey](),
		),
	}

	return infisicalClient, nil
}

func ParseRawECPublicKey(publicKeyBytes []byte) (*ecdsa.PublicKey, error) {

	if len(publicKeyBytes) != 65 || publicKeyBytes[0] != 0x04 {
		return nil, fmt.Errorf("invalid public key format: expected uncompressed point (0x04 + X + Y)")
	}

	x := new(big.Int).SetBytes(publicKeyBytes[1:33])
	y := new(big.Int).SetBytes(publicKeyBytes[33:65])

	pubKey := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     x,
		Y:     y,
	}

	return pubKey, nil
}

func (h *infisicalClient) fetchPublicKey(_ context.Context) (crypto.PublicKey, error) {

	kmsKey, err := h.client.Kms().Keys().GetByName(infisical.KmsGetKeyByNameOptions{
		KeyName:   h.keyName,
		ProjectId: h.projectId,
	})

	if err != nil {
		return nil, fmt.Errorf("getting key by name: %w", err)
	}

	publicKeyEncoded, err := h.client.Kms().Signing().GetPublicKey(infisical.KmsGetPublicKeyOptions{
		KeyId: kmsKey.KeyId,
	})
	if err != nil {
		return nil, fmt.Errorf("getting public key: %w", err)
	}

	// all public keys are wrapped with base64 encoding
	publicKeyBase64ToBytes, err := base64.StdEncoding.DecodeString(publicKeyEncoded)
	if err != nil {
		return nil, fmt.Errorf("decoding public key base64: %w", err)
	}

	if strings.Contains(kmsKey.EncryptionAlgorithm, "ECC") {
		// Parse the public key for ECC
		parsedKey, err := x509.ParsePKIXPublicKey(publicKeyBase64ToBytes)
		if err != nil {
			return nil, fmt.Errorf("parsing ECC public key: %w", err)
		}

		// Convert to ECC public key type
		eccKey, ok := parsedKey.(*ecdsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("public key is not a valid ECDSA key")
		}

		return eccKey, nil

	} else if strings.Contains(kmsKey.EncryptionAlgorithm, "RSA") {

		decodedPublicKey, err := base64.StdEncoding.DecodeString(publicKeyEncoded)
		if err != nil {
			return nil, fmt.Errorf("decoding public key base64: %w", err)
		}

		return x509.ParsePKIXPublicKey(decodedPublicKey)

	}

	// now handle rsa public key

	return nil, fmt.Errorf("invalid public key format")
}

func (h *infisicalClient) public() (crypto.PublicKey, error) {
	var lerr error
	loader := ttlcache.LoaderFunc[string, crypto.PublicKey](
		func(c *ttlcache.Cache[string, crypto.PublicKey], key string) *ttlcache.Item[string, crypto.PublicKey] {
			var pubkey crypto.PublicKey
			pubkey, lerr = h.fetchPublicKey(context.Background())
			if lerr == nil {
				item := c.Set(key, pubkey, 300*time.Second)
				return item
			}
			return nil
		},
	)

	item := h.keyCache.Get(cacheKey, ttlcache.WithLoader[string, crypto.PublicKey](loader))
	if lerr != nil {
		return nil, lerr
	}

	if item == nil {
		return nil, fmt.Errorf("unable to retrieve an item from the cache by the provided key")
	}

	return item.Value(), nil
}

func FormatECDSASignature(signature []byte) ([]byte, error) {

	// Try to parse as a standard ECDSA signature
	var sig struct {
		R, S *big.Int
	}

	// Attempt to unmarshal the ASN.1 structure
	rest, err := asn1.Unmarshal(signature, &sig)
	if err != nil {
		return nil, fmt.Errorf("failed to parse ASN.1 signature: %w", err)
	}

	// Ensure there's no trailing data
	if len(rest) > 0 {
		return nil, fmt.Errorf("unexpected %d bytes after ASN.1 signature", len(rest))
	}

	// Validate that R and S are present and non-nil
	if sig.R == nil || sig.S == nil {
		return nil, fmt.Errorf("invalid signature: R or S value is missing")
	}

	// Re-encode using Go's standard ASN.1 encoding for ECDSA
	return asn1.Marshal(struct {
		R, S *big.Int
	}{
		R: sig.R,
		S: sig.S,
	})
}

func (h infisicalClient) sign(digest []byte, alg crypto.Hash) ([]byte, error) {

	kmsKey, err := h.client.Kms().Keys().GetByName(infisical.KmsGetKeyByNameOptions{
		KeyName:   h.keyName,
		ProjectId: h.projectId,
	})

	if err != nil {
		return nil, fmt.Errorf("getting key: %w", err)
	}
	publicKey, err := h.public()
	if err != nil {
		return nil, fmt.Errorf("getting key: %w", err)
	}

	ecdsaPub, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("public key is not a valid ECDSA key")
	}

	selectedAlgorithm, err := h.GetSigningAlgorithm(kmsKey.KeyId, kmsKey.EncryptionAlgorithm, alg)

	if err != nil {
		return nil, fmt.Errorf("getting signing algorithm: %w", err)
	}

	signature, err := h.client.Kms().Signing().SignData(infisical.KmsSignDataOptions{
		KeyId:            kmsKey.KeyId,
		Data:             base64.StdEncoding.Strict().EncodeToString(digest),
		SigningAlgorithm: selectedAlgorithm,     // only relevant if its not a digest
		IsDigest:         alg != crypto.Hash(0), // if alg is 0, it means the data is NOT a digest
	})

	os.Stderr.WriteString(fmt.Sprintf("Selected Algorithm: %s\n", selectedAlgorithm))
	os.Stderr.WriteString(fmt.Sprintf("Input data (digest): %s\n", base64.StdEncoding.Strict().EncodeToString(digest)))
	os.Stderr.WriteString(fmt.Sprintf("Signature in base64: %s\n", base64.StdEncoding.Strict().EncodeToString(signature)))
	os.Stderr.WriteString(fmt.Sprintf("Is Digest: %t\n", alg != crypto.Hash(0)))

	if err != nil {
		return nil, fmt.Errorf("sign: %w", err)
	}

	normalizedSignature, err := NormalizeECDSASignature(signature, ecdsaPub)

	if err != nil {
		return nil, fmt.Errorf("normalizing signature: %w", err)
	}

	return normalizedSignature, nil
}

func (h infisicalClient) createKey(algorithm string) (crypto.PublicKey, error) {

	_, err := h.client.Kms().Keys().Create(infisical.KmsCreateKeyOptions{
		KeyUsage:            "sign-verify",
		Description:         "sigstore-kms-key",
		EncryptionAlgorithm: algorithm,
		ProjectId:           h.projectId,
		Name:                h.keyName,
	})

	if err != nil {
		return nil, fmt.Errorf("create key: %w", err)
	}

	return h.public()
}
