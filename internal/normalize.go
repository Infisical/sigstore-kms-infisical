package infisical2

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/asn1"
	"fmt"
	"math/big"
)

// ECDSASignature represents the two integers (r,s) in an ECDSA signature
type ECDSASignature struct {
	R, S *big.Int
}

// NormalizeECDSASignature takes a base64-encoded signature and the public key's curve,
// normalizes the S value of the signature (ensuring it's in the lower half of the curve order),
// and re-encodes it as an ASN.1 DER signature.
func NormalizeECDSASignature(sigBytes []byte, curve elliptic.Curve) ([]byte, error) {

	// Parse the ASN.1 DER encoded signature
	var sig ECDSASignature
	_, err := asn1.Unmarshal(sigBytes, &sig)
	if err != nil {
		return nil, fmt.Errorf("failed to parse signature as ASN.1: %w", err)
	}

	// Get the curve order (N)
	N := curve.Params().N

	// Check if S is in the upper half of the curve order
	halfOrder := new(big.Int).Rsh(N, 1) // N/2
	if sig.S.Cmp(halfOrder) > 0 {
		// If S is in the upper half, replace it with N - S
		sig.S = new(big.Int).Sub(N, sig.S)
	}

	// Re-encode the normalized signature as ASN.1 DER
	normalizedSig, err := asn1.Marshal(sig)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal normalized signature: %w", err)
	}

	return normalizedSig, nil
}

// NormalizeSignatureFromPublicKey takes a signature and public key, then normalizes
// the signature based on the curve of the public key
func NormalizeSignatureFromPublicKey(signature []byte, publicKey *ecdsa.PublicKey) ([]byte, error) {
	// Parse the ASN.1 DER encoded signature
	var sig ECDSASignature
	_, err := asn1.Unmarshal(signature, &sig)
	if err != nil {
		return nil, fmt.Errorf("failed to parse signature as ASN.1: %w", err)
	}

	// Get the curve order (N)
	N := publicKey.Curve.Params().N

	// Check if S is in the upper half of the curve order
	halfOrder := new(big.Int).Rsh(N, 1) // N/2
	if sig.S.Cmp(halfOrder) > 0 {
		// If S is in the upper half, replace it with N - S
		sig.S = new(big.Int).Sub(N, sig.S)
	}

	// Re-encode the normalized signature as ASN.1 DER
	normalizedSig, err := asn1.Marshal(sig)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal normalized signature: %w", err)
	}

	return normalizedSig, nil
}
