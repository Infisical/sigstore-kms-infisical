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
	SigningAlgorithmRSA_PKCS1_V1_5_SHA_512 = "RSASSA_PKCS1_V1_5_SHA_512"
	SigningAlgorithmRSA_PKCS1_V1_5_SHA_384 = "RSASSA_PKCS1_V1_5_SHA_384"
	SigningAlgorithmRSA_PKCS1_V1_5_SHA_256 = "RSASSA_PKCS1_V1_5_SHA_256"
	SigningAlgorithmECDSA_SHA_512          = "ECDSA_SHA_512"
	SigningAlgorithmECDSA_SHA_384          = "ECDSA_SHA_384"
	SigningAlgorithmECDSA_SHA_256          = "ECDSA_SHA_256"
	KeyAlgorithmRSA_4096                   = "RSA_4096"
	KeyAlgorithmECC_NIST_P256              = "ECC_NIST_P256"
)

var infisicalSupportedEncryptionAlgorithms = []string{
	KeyAlgorithmRSA_4096,
	KeyAlgorithmECC_NIST_P256,
}

// InfisicalSignerVerifier creates and verifies digital signatures with a key saved at KeyResourceID,
// and implements signerverifier.SignerVerifier.
type InfisicalSignerVerifier struct {
	keyResourceID string
	hashFunc      crypto.Hash
}

// DefaultAlgorithm returns the default algorithm for the signer.
func (i InfisicalSignerVerifier) DefaultAlgorithm() string {
	return KeyAlgorithmRSA_4096
}

// SupportedAlgorithms returns the supported algorithms for the signer.
func (i InfisicalSignerVerifier) SupportedAlgorithms() []string {
	return infisicalSupportedEncryptionAlgorithms
}

func (i InfisicalSignerVerifier) CreateKey(ctx context.Context, algorithm string) (crypto.PublicKey, error) {

	projectId := os.Getenv("INFISICAL_PROJECT_ID")
	if projectId == "" {
		return nil, fmt.Errorf("INFISICAL_PROJECT_ID is not set")
	}

	infisicalClient, err := i.getInfisicalClient()
	if err != nil {
		return nil, fmt.Errorf("unable to get infisical client: %s", err)
	}

	kmsKey, err := i.getInfisicalKmsKey(infisicalClient, i.keyResourceID)
	if err == nil {
		if kmsKey.EncryptionAlgorithm != algorithm {
			return nil, fmt.Errorf("kms key with name '%s' already exists, but with a different algorithm. The existing key has the algorithm '%s' and the requested algorithm is '%s'", i.keyResourceID, kmsKey.EncryptionAlgorithm, algorithm)
		}
		return i.fetchPublicKey(ctx)
	}

	_, err = infisicalClient.Kms().Keys().Create(infisical.KmsCreateKeyOptions{
		KeyUsage:            "sign-verify",
		Name:                i.keyResourceID,
		ProjectId:           projectId,
		Description:         "Created by sigstore-kms-infisical",
		EncryptionAlgorithm: algorithm,
	})
	if err != nil {
		return nil, fmt.Errorf("unable to create kms key: %s", err)
	}

	return i.fetchPublicKey(ctx)

}

// PublicKey returns the public key.
func (i InfisicalSignerVerifier) PublicKey(opts ...signature.PublicKeyOption) (crypto.PublicKey, error) {
	return i.fetchPublicKey(context.Background())
}

func (i InfisicalSignerVerifier) getInfisicalClient() (infisicalClient infisical.InfisicalClientInterface, err error) {

	siteUrl := os.Getenv("INFISICAL_SITE_URL")
	universalAuthClientId := os.Getenv("INFISICAL_UNIVERSAL_AUTH_CLIENT_ID")
	universalAuthClientSecret := os.Getenv("INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET")

	if siteUrl == "" {
		siteUrl = "https://app.infisical.com"
	}

	if universalAuthClientId == "" {
		return nil, fmt.Errorf("INFISICAL_UNIVERSAL_AUTH_CLIENT_ID is not set")
	}

	if universalAuthClientSecret == "" {
		return nil, fmt.Errorf("INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET is not set")
	}

	infisicalClient = infisical.NewInfisicalClient(context.Background(), infisical.Config{
		SiteUrl: siteUrl,
	})

	_, err = infisicalClient.Auth().UniversalAuthLogin(universalAuthClientId, universalAuthClientSecret)

	if err != nil {
		return nil, fmt.Errorf("unable to connect to infisical: %s", err)
	}

	return infisicalClient, nil
}

func (i InfisicalSignerVerifier) getInfisicalKmsKey(infisicalClient infisical.InfisicalClientInterface, keyResourceID string) (infisical.KmsGetKeyResult, error) {
	projectId := os.Getenv("INFISICAL_PROJECT_ID")
	if projectId == "" {
		return infisical.KmsGetKeyResult{}, fmt.Errorf("INFISICAL_PROJECT_ID is not set")
	}

	return infisicalClient.Kms().Keys().GetByName(infisical.KmsGetKeyByNameOptions{
		KeyName:   keyResourceID,
		ProjectId: projectId,
	})
}

// SignMessage signs the message with the KeyResourceID.
func (i InfisicalSignerVerifier) SignMessage(message io.Reader, opts ...signature.SignOption) ([]byte, error) {
	infisicalClient, err := i.getInfisicalClient()
	if err != nil {
		return nil, fmt.Errorf("unable to get infisical client: %s", err)
	}
	kmsKey, err := i.getInfisicalKmsKey(infisicalClient, i.keyResourceID)
	if err != nil {
		return nil, fmt.Errorf("unable to get kms key: %s", err)
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

	signingAlgorithm, err := getSigningAlgorithmFromHashFunction(i.hashFunc, kmsKey)
	if err != nil {
		return nil, fmt.Errorf("error getting signing algorithm: %w", err)
	}

	sig, err := infisicalClient.Kms().Signing().SignData(infisical.KmsSignDataOptions{
		KeyId:            kmsKey.KeyId,
		Data:             base64.StdEncoding.Strict().EncodeToString(digest),
		SigningAlgorithm: signingAlgorithm,
		IsPreDigested:    i.hashFunc != crypto.Hash(0),
	})

	if err != nil {
		return nil, fmt.Errorf("unable to sign: %s", err)
	}

	return sig, nil
}

func getSigningAlgorithmFromHashFunction(hashFunc crypto.Hash, kmsKey infisical.KmsGetKeyResult) (string, error) {

	if hashFunc == crypto.Hash(0) {
		if strings.Contains(kmsKey.EncryptionAlgorithm, "ECC") {
			return SigningAlgorithmECDSA_SHA_256, nil
		} else if strings.Contains(kmsKey.EncryptionAlgorithm, "RSA") {
			return SigningAlgorithmRSA_PKCS1_V1_5_SHA_256, nil
		}
	}

	if strings.Contains(kmsKey.EncryptionAlgorithm, "ECC") {
		if hashFunc == crypto.SHA256 {
			return SigningAlgorithmECDSA_SHA_256, nil
		} else if hashFunc == crypto.SHA384 {
			return SigningAlgorithmECDSA_SHA_384, nil
		} else if hashFunc == crypto.SHA512 {
			return SigningAlgorithmECDSA_SHA_512, nil
		}
	} else if strings.Contains(kmsKey.EncryptionAlgorithm, "RSA") {
		if hashFunc == crypto.SHA256 {
			return SigningAlgorithmRSA_PKCS1_V1_5_SHA_256, nil
		} else if hashFunc == crypto.SHA384 {
			return SigningAlgorithmRSA_PKCS1_V1_5_SHA_384, nil
		} else if hashFunc == crypto.SHA512 {
			return SigningAlgorithmRSA_PKCS1_V1_5_SHA_512, nil
		}
	}

	return "", fmt.Errorf("unsupported hash function: %s", hashFunc)
}

// VerifySignature verifies the signature.
func (i InfisicalSignerVerifier) VerifySignature(signature io.Reader, message io.Reader, opts ...signature.VerifyOption) error {

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
func (i InfisicalSignerVerifier) CryptoSigner(ctx context.Context, errFunc func(error)) (crypto.Signer, crypto.SignerOpts, error) {
	panic("Infisical KMS does not implement CryptoSigner()")
}

func (i *InfisicalSignerVerifier) fetchPublicKey(_ context.Context) (crypto.PublicKey, error) {
	infisicalClient, err := i.getInfisicalClient()
	if err != nil {
		return nil, fmt.Errorf("unable to get infisical client: %s", err)
	}

	kmsKey, err := i.getInfisicalKmsKey(infisicalClient, i.keyResourceID)
	if err != nil {
		return nil, fmt.Errorf("unable to get kms key: %s", err)
	}

	publicKeyEncoded, err := infisicalClient.Kms().Signing().GetPublicKey(infisical.KmsGetPublicKeyOptions{
		KeyId: kmsKey.KeyId,
	})
	if err != nil {
		return nil, fmt.Errorf("getting public key: %w", err)
	}

	publicKeyBase64ToBytes, err := base64.StdEncoding.DecodeString(publicKeyEncoded)
	if err != nil {
		return nil, fmt.Errorf("decoding public key base64: %w", err)
	}

	if strings.Contains(kmsKey.EncryptionAlgorithm, "ECC") {
		parsedKey, err := x509.ParsePKIXPublicKey(publicKeyBase64ToBytes)
		if err != nil {
			return nil, fmt.Errorf("parsing ECC public key: %w", err)
		}

		eccKey, ok := parsedKey.(*ecdsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("public key is not a valid ECDSA key")
		}

		return eccKey, nil

	} else if strings.Contains(kmsKey.EncryptionAlgorithm, "RSA") {
		return x509.ParsePKIXPublicKey(publicKeyBase64ToBytes)
	}

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
