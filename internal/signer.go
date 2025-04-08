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

package infisical2

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"

	infisical "github.com/infisical/go-sdk"
	"github.com/sigstore/sigstore/pkg/signature"
)

const (
	AlgorithmRSA_PKCS1_V1_5_SHA_512 = "RSASSA_PKCS1_V1_5_SHA_512"
	AlgorithmRSA_PKCS1_V1_5_SHA_384 = "RSASSA_PKCS1_V1_5_SHA_384"
	AlgorithmRSA_PKCS1_V1_5_SHA_256 = "RSASSA_PKCS1_V1_5_SHA_256"
	AlgorithmECDSA_SHA_512          = "ECDSA_SHA_512"
	AlgorithmECDSA_SHA_384          = "ECDSA_SHA_384"
	AlgorithmECDSA_SHA_256          = "ECDSA_SHA_256"
)

var infisicalSupportedAlgorithms = []string{
	AlgorithmRSA_PKCS1_V1_5_SHA_512,
	AlgorithmRSA_PKCS1_V1_5_SHA_384,
	AlgorithmRSA_PKCS1_V1_5_SHA_256,
	AlgorithmECDSA_SHA_512,
	AlgorithmECDSA_SHA_384,
	AlgorithmECDSA_SHA_256,
}
var infisicalSupportedHashFuncs = []crypto.Hash{
	crypto.SHA256,
	crypto.SHA384,
	crypto.SHA512,
	crypto.Hash(0),
}

func (h *infisicalClient) GetSigningAlgorithm(keyId string, kmsKeyEncryptionAlgorithm string, alg crypto.Hash) (string, error) {

	supportedSigningAlgorithms, err := h.client.Kms().Signing().ListSigningAlgorithms(infisical.KmsListSigningAlgorithmsOptions{
		KeyId: keyId,
	})
	if err != nil {
		return "", fmt.Errorf("listing signing algorithms: %w", err)
	}

	var filteredAlgorithms []string
	var selectedAlgorithm string

	for _, algorithm := range supportedSigningAlgorithms {
		if !strings.HasPrefix(algorithm, "RSASSA_PSS") {
			filteredAlgorithms = append(filteredAlgorithms, algorithm)
		}
	}

	// if alg is 0, we just pick the first algorithm, because we know the data is not a digest and we don't need to match the hash function
	if alg == crypto.Hash(0) {
		selectedAlgorithm = filteredAlgorithms[0]
	} else {
		switch alg {
		case crypto.SHA256:
			// find any algorithm in supportedSigningAlgorithms that ends with SHA_256
			for _, algorithm := range filteredAlgorithms {
				if strings.HasSuffix(algorithm, "SHA_256") {
					selectedAlgorithm = algorithm
					break
				}
			}
		case crypto.SHA384:
			// find any algorithm in supportedSigningAlgorithms that ends with SHA_384
			for _, algorithm := range filteredAlgorithms {
				if strings.HasSuffix(algorithm, "SHA_384") {
					selectedAlgorithm = algorithm
					break
				}
			}
		case crypto.SHA512:
			// find any algorithm in supportedSigningAlgorithms that ends with SHA_512
			for _, algorithm := range filteredAlgorithms {
				if strings.HasSuffix(algorithm, "SHA_512") {
					selectedAlgorithm = algorithm
					break
				}
			}
		default:
			return "", fmt.Errorf("hash function not supported by Infisical")
		}
	}

	if !slices.Contains(infisicalSupportedAlgorithms, selectedAlgorithm) {
		return "", fmt.Errorf("signing algorithm '%s' not supported by key type '%s'", selectedAlgorithm, kmsKeyEncryptionAlgorithm)
	}

	return selectedAlgorithm, nil
}

// SignerVerifier creates and verifies digital signatures over a message using Infisical KMS service
type SignerVerifier struct {
	hashFunc crypto.Hash
	client   *infisicalClient
}

// LoadSignerVerifier generates signatures using the specified key object in Vault and hash algorithm.
//
// It also can verify signatures (via a remote vall to the Vault instance). hashFunc should be
// set to crypto.Hash(0) if the key referred to by referenceStr is an ED25519 signing key.
func LoadSignerVerifier(referenceStr string, opts ...signature.RPCOption) (*SignerVerifier, error) {
	h := &SignerVerifier{}

	var err error
	h.client, err = newInfisicalClient(referenceStr)
	if err != nil {
		return nil, err
	}

	// currently not configurable, we'll extend this in the future upon request. both ecc and rsa support sha512
	hashFunc := crypto.SHA512

	switch hashFunc {
	case 0, crypto.SHA224, crypto.SHA256, crypto.SHA384, crypto.SHA512:
		h.hashFunc = hashFunc
	default:
		return nil, errors.New("hash function not supported by Infisical")
	}

	return h, nil
}

// SignMessage signs the provided message using Infisical KMS. If the message is provided,
// this method will compute the digest according to the hash function specified
// when the InfisicalSigner was created.
//
// SignMessage recognizes the following Options listed in order of preference:
//
// - WithDigest()
//
// All other options are ignored if specified.

func (h SignerVerifier) SignMessage(message io.Reader, opts ...signature.SignOption) ([]byte, error) {
	var digest []byte
	var signerOpts crypto.SignerOpts = h.hashFunc

	for _, opt := range opts {
		opt.ApplyDigest(&digest)
		opt.ApplyCryptoSignerOpts(&signerOpts)
	}

	digest, err := computeDigest(&message, signerOpts.HashFunc())
	if err != nil {
		return nil, err
	}
	os.Stderr.WriteString(fmt.Sprintf("Using hash function to sign digest: [result=%s], [request=%s]\n", signerOpts.HashFunc(), signerOpts.HashFunc()))
	os.Stderr.WriteString(fmt.Sprintf("Digest: %s\n", base64.StdEncoding.Strict().EncodeToString(digest)))

	return h.client.sign(digest, signerOpts.HashFunc())
}

// PublicKey returns the public key that can be used to verify signatures created by
// this signer. All options provided in arguments to this method are ignored.
func (h SignerVerifier) PublicKey(_ ...signature.PublicKeyOption) (crypto.PublicKey, error) {

	fmt.Printf("IN PUBLIC KEY\n")
	fmt.Printf("IN PUBLIC KEY\n")
	fmt.Printf("IN PUBLIC KEY\n")
	fmt.Printf("IN PUBLIC KEY\n")
	fmt.Printf("IN PUBLIC KEY\n")
	fmt.Printf("IN PUBLIC KEY\n")

	return h.client.public()
}

// VerifySignature verifies the signature.
func (i SignerVerifier) VerifySignature(signature io.Reader, message io.Reader, opts ...signature.VerifyOption) error {
	fmt.Printf("IN VERIFY SIGNATURE\n")
	fmt.Printf("IN VERIFY SIGNATURE\n")
	fmt.Printf("IN VERIFY SIGNATURE\n")
	fmt.Printf("IN VERIFY SIGNATURE\n")
	fmt.Printf("IN VERIFY SIGNATURE\n")
	fmt.Printf("IN VERIFY SIGNATURE\n")
	ctx := context.Background()
	for _, opt := range opts {
		opt.ApplyContext(&ctx)
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	publicKey, err := i.PublicKey()
	if err != nil {
		return fmt.Errorf("error loading public key: %w", err)
	}
	var digest []byte
	var signerOpts crypto.SignerOpts = i.hashFunc
	for _, opt := range opts {
		opt.ApplyDigest(&digest)
		opt.ApplyCryptoSignerOpts(&signerOpts)
	}

	if len(digest) == 0 {
		digest, err = computeDigest(&message, signerOpts.HashFunc())
		if err != nil {
			return err
		}
	}

	sig, err := io.ReadAll(signature)
	if err != nil {
		return fmt.Errorf("error reading signature: %w", err)
	}

	msg, err := io.ReadAll(message)
	if err != nil {
		return fmt.Errorf("error reading message: %w", err)
	}

	switch publicKey.(type) {
	case *rsa.PublicKey:
		if err := rsa.VerifyPKCS1v15(publicKey.(*rsa.PublicKey), signerOpts.HashFunc(), digest, sig); err != nil {
			return fmt.Errorf("error verifying signature: %w", err)
		}
	case *ecdsa.PublicKey:
		if !ecdsa.VerifyASN1(publicKey.(*ecdsa.PublicKey), digest, sig) {
			return fmt.Errorf("failed verification")
		}
	case ed25519.PublicKey:
		if !ed25519.Verify(publicKey.(ed25519.PublicKey), msg, sig) {
			return fmt.Errorf("failed verification")
		}
	default:
		if err := rsa.VerifyPKCS1v15(publicKey.(*rsa.PublicKey), signerOpts.HashFunc(), digest, sig); err != nil {
			return fmt.Errorf("error verifying signature: %w", err)
		}
	}

	return nil
}

func (c *infisicalClient) Verifier(algorithm crypto.Hash) (signature.Verifier, error) {

	kmsKey, err := c.client.Kms().Keys().GetByName(infisical.KmsGetKeyByNameOptions{
		KeyName:   c.keyName,
		ProjectId: c.projectId,
	})

	if err != nil {
		return nil, fmt.Errorf("getting key by name: %w", err)
	}

	signingAlgorithm, err := c.GetSigningAlgorithm(kmsKey.KeyId, kmsKey.EncryptionAlgorithm, algorithm)
	if err != nil {
		return nil, fmt.Errorf("getting signing algorithm: %w", err)
	}

	publicKey, err := c.public()
	if err != nil {
		return nil, fmt.Errorf("getting public key: %w", err)
	}

	switch signingAlgorithm {
	case AlgorithmRSA_PKCS1_V1_5_SHA_256, AlgorithmRSA_PKCS1_V1_5_SHA_384, AlgorithmRSA_PKCS1_V1_5_SHA_512:
		pub, ok := publicKey.(*rsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("public key is not rsa")
		}
		return signature.LoadRSAPKCS1v15Verifier(pub, algorithm)
	case AlgorithmECDSA_SHA_256, AlgorithmECDSA_SHA_384, AlgorithmECDSA_SHA_512:
		pub, ok := publicKey.(*ecdsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("public key is not ecdsa")
		}
		return signature.LoadECDSAVerifier(pub, algorithm)
	default:
		return nil, fmt.Errorf("signing algorithm unsupported")
	}
}

func (a *infisicalClient) verify(ctx context.Context, sig, message io.Reader, opts ...signature.VerifyOption) error {
	verifier, err := a.Verifier(crypto.SHA512)
	if err != nil {
		return err
	}
	return verifier.VerifySignature(sig, message, opts...)
}

func (h SignerVerifier) CreateKey(_ context.Context, algorithm string) (crypto.PublicKey, error) {

	kmsKey, err := h.client.client.Kms().Keys().GetByName(infisical.KmsGetKeyByNameOptions{
		KeyName:   h.client.keyName,
		ProjectId: h.client.projectId,
	})

	if err == nil {
		if algorithm != kmsKey.EncryptionAlgorithm {
			return nil, fmt.Errorf("key with name '%s' already exists with a different algorithm (%s). you attempted to create a key with algorithm '%s'", h.client.keyName, kmsKey.EncryptionAlgorithm, algorithm)
		}

		h.client.keyName = kmsKey.Name
		return h.client.public()
	}

	return h.client.createKey(algorithm)
}

func (i SignerVerifier) CryptoSigner(ctx context.Context, errFunc func(error)) (crypto.Signer, crypto.SignerOpts, error) {
	panic("CryptoSigner is not implemented")
}

// SupportedAlgorithms returns the list of algorithms supported by the Infisical service
func (h *SignerVerifier) SupportedAlgorithms() []string {
	return infisicalSupportedAlgorithms
}

// DefaultAlgorithm returns the default algorithm for the Infisical service
func (h *SignerVerifier) DefaultAlgorithm() string {
	return AlgorithmRSA_PKCS1_V1_5_SHA_512
}

func computeDigest(message *io.Reader, hashFunc crypto.Hash) ([]byte, error) {
	hasher := hashFunc.New()
	if _, err := io.Copy(hasher, *message); err != nil {
		return nil, err
	}
	return hasher.Sum(nil), nil
}
