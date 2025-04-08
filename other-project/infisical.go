package main

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"strings"

	infisical "github.com/infisical/go-sdk"
	"github.com/sigstore/sigstore/pkg/signature"
)

const (
	defaultAlgorithm = "rsa-4096"
)

var (
	supportedAlgorithms = []string{defaultAlgorithm}
)

// VenafiSignerVerifier creates and verifies digital signatures with a key saved at KeyResourceID,
// and implements signerverifier.SignerVerifier.
type VenafiSignerVerifier struct {
	keyResourceID string
	hashFunc      crypto.Hash
}

// DefaultAlgorithm returns the default algorithm for the signer.
func (i VenafiSignerVerifier) DefaultAlgorithm() string {
	return defaultAlgorithm
}

// SupportedAlgorithms returns the supported algorithms for the signer.
func (i VenafiSignerVerifier) SupportedAlgorithms() []string {
	return supportedAlgorithms
}

// Not currently implemented for Venafi CodeSign Protect
func (i VenafiSignerVerifier) CreateKey(ctx context.Context, algorithm string) (crypto.PublicKey, error) {
	return nil, fmt.Errorf("generate-key-pair not implemented for Venafi CodeSign Protect")
}

// PublicKey returns the public key.
func (i VenafiSignerVerifier) PublicKey(opts ...signature.PublicKeyOption) (crypto.PublicKey, error) {
	return i.fetchPublicKey(context.Background())
}

// SignMessage signs the message with the KeyResourceID.
func (i VenafiSignerVerifier) SignMessage(message io.Reader, opts ...signature.SignOption) ([]byte, error) {

	infisicalClient := infisical.NewInfisicalClient(context.Background(), infisical.Config{
		SiteUrl: "http://localhost:8080",
	})

	_, err := infisicalClient.Auth().UniversalAuthLogin("f66716d8-874d-4456-9f59-5b5185e2518c", "eecb8b2a0b4381e267f6ca1ced91283be4f480089a86c137132c38e9e40d1b60")

	if err != nil {
		return nil, fmt.Errorf("unable to connect to infisical: %s", err)
	}

	kmsKey, err := infisicalClient.Kms().Keys().GetByName(infisical.KmsGetKeyByNameOptions{
		KeyName:   i.keyResourceID,
		ProjectId: "c54edf7a-f861-4131-afdc-b0ad5faec5dc",
	})
	if err != nil {
		return nil, fmt.Errorf("unable to get key: %s", err)
	}

	var digest []byte
	for _, opt := range opts {
		opt.ApplyDigest(&digest)
	}

	// Only compute digest if one wasn't provided
	if len(digest) == 0 {
		var err error
		digest, err = computeDigest(&message, i.hashFunc)
		if err != nil {
			return nil, fmt.Errorf("error computing digest: %w", err)
		}
	}

	sig, err := infisicalClient.Kms().Signing().SignData(infisical.KmsSignDataOptions{
		KeyId:            kmsKey.KeyId,
		Data:             base64.StdEncoding.Strict().EncodeToString(digest),
		SigningAlgorithm: "RSASSA_PKCS1_V1_5_SHA_256",
		IsDigest:         i.hashFunc != crypto.Hash(0),
	})

	if err != nil {
		return nil, fmt.Errorf("unable to sign: %s", err)
	}

	return sig, nil
}

// VerifySignature verifies the signature.
func (i VenafiSignerVerifier) VerifySignature(signature io.Reader, message io.Reader, opts ...signature.VerifyOption) error {

	ctx := context.Background()
	for _, opt := range opts {
		opt.ApplyContext(&ctx)
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	publicKey, err := i.fetchPublicKey(ctx)
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

	decodedSig, err := base64.StdEncoding.DecodeString(string(sig))
	if err == nil { // Only use decoded signature if decoding succeeds
		os.Stderr.WriteString("Decoded signature: " + string(decodedSig) + "\n")
		sig = decodedSig
	}

	msg, err := io.ReadAll(message)
	if err != nil {
		return fmt.Errorf("error reading message: %w", err)
	}

	switch publicKey.(type) {
	case *rsa.PublicKey:
		if err := rsa.VerifyPKCS1v15(publicKey.(*rsa.PublicKey), signerOpts.HashFunc(), digest, sig); err != nil {
			return fmt.Errorf("error verifying rsa pkcs1v15 signature: %w", err)
		}
	case *ecdsa.PublicKey:
		if !ecdsa.VerifyASN1(publicKey.(*ecdsa.PublicKey), digest, sig) {
			return fmt.Errorf("failed verification for ecdsa asn1")
		}
	case ed25519.PublicKey:
		if !ed25519.Verify(publicKey.(ed25519.PublicKey), msg, sig) {
			return fmt.Errorf("failed verification for ed25519")
		}
	default:
		if err := rsa.VerifyPKCS1v15(publicKey.(*rsa.PublicKey), signerOpts.HashFunc(), digest, sig); err != nil {
			return fmt.Errorf("default fallback, error verifying signature for rsa pkcs1v15: %w", err)
		}
	}

	return nil
}

// CryptoSigner need not be fully implemented by plugins.
func (i VenafiSignerVerifier) CryptoSigner(ctx context.Context, errFunc func(error)) (crypto.Signer, crypto.SignerOpts, error) {
	panic("CryptoSigner() not implemented")
}

func (i *VenafiSignerVerifier) fetchPublicKey(_ context.Context) (crypto.PublicKey, error) {
	infisicalClient := infisical.NewInfisicalClient(context.Background(), infisical.Config{
		SiteUrl: "http://localhost:8080",
	})

	_, err := infisicalClient.Auth().UniversalAuthLogin("f66716d8-874d-4456-9f59-5b5185e2518c", "eecb8b2a0b4381e267f6ca1ced91283be4f480089a86c137132c38e9e40d1b60")

	if err != nil {
		return nil, fmt.Errorf("unable to connect to infisical: %s", err)
	}

	kmsKey, err := infisicalClient.Kms().Keys().GetByName(infisical.KmsGetKeyByNameOptions{
		KeyName:   i.keyResourceID,
		ProjectId: "c54edf7a-f861-4131-afdc-b0ad5faec5dc",
	})

	if err != nil {
		return nil, fmt.Errorf("getting key by name: %w", err)
	}

	publicKeyEncoded, err := infisicalClient.Kms().Signing().GetPublicKey(infisical.KmsGetPublicKeyOptions{
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
		// Decode the base64-encoded public key only ONCE
		decodedPublicKey, err := base64.StdEncoding.DecodeString(publicKeyEncoded)
		if err != nil {
			return nil, fmt.Errorf("decoding public key base64: %w", err)
		}

		// Parse the DER-encoded SPKI public key
		return x509.ParsePKIXPublicKey(decodedPublicKey)
	}

	// now handle rsa public key

	return nil, fmt.Errorf("invalid public key format")
}

// computeDigest computes the message digest with the hash function.
func computeDigest(message *io.Reader, hashFunc crypto.Hash) ([]byte, error) {
	hasher := hashFunc.New()
	if _, err := io.Copy(hasher, *message); err != nil {
		return nil, err
	}
	return hasher.Sum(nil), nil
}
