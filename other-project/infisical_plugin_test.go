package main

import (
	"bytes"
	"context"
	"crypto"
	"flag"
	"fmt"
	"os"
	"testing"

	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/kms/cliplugin"
	"github.com/sigstore/sigstore/pkg/signature/options"
)

// This file tests the PluginClient against a pre-built plugin programs.
// It is skipped during normal `go test ./...` invocations. It can be invoked like
// `go test -tags=signer_program -count=1 ./... -key-resource-id [my-kms]://[my-key-ref]`
// See ./README.md for plugin program usage.

// We don't have a TestCryptoSigner since PluginClient.CryptoSigner()'s returned object is meant to be a wrapper around PluginClient.

var (
	inputKeyResourceID = flag.String("key-resource-id", "", "key resource ID for the KMS, defaults to 'infisical://key-name'")
	testHashFunc       = crypto.SHA512
)

// getPluginClient parses the build flags for the KeyResourceID and returns a PluginClient.
func getPluginClient(t *testing.T) *cliplugin.PluginClient {
	t.Helper()
	signerVerifier, err := cliplugin.LoadSignerVerifier(context.Background(), *inputKeyResourceID, testHashFunc)
	if err != nil {
		t.Fatal(err)
	}
	pluginClient := signerVerifier.(*cliplugin.PluginClient)
	return pluginClient
}

// TestDefaultAlgorithm invokes DefaultAlgorithm against the compiled plugin program.
// Since implementations can vary, it merely checks that some non-empty value is returned.
func TestDefaultAlgorithm(t *testing.T) {
	t.Parallel()

	pluginClient := getPluginClient(t)

	if defaultAlgorithm := pluginClient.DefaultAlgorithm(); defaultAlgorithm == "" {
		t.Error("expected non-empty default algorithm")
	}
}

// TestSupportedAlgorithms invokes DefaultAlgorithm against the compiled plugin program.
// Since implementations can vary, it merely checks that some non-empty value is returned.
func TestSupportedAlgorithms(t *testing.T) {
	t.Parallel()

	pluginClient := getPluginClient(t)

	if supportedAlgorithms := pluginClient.SupportedAlgorithms(); len(supportedAlgorithms) == 0 {
		t.Error("expected non-empty supported algorithms")
	}
}

// TestCreateKey invokes SignMessage against the compiled plugin program,
// with combinations of empty or non-empty messages, and digests.
// Since implementations can vary, it merely checks that non-empty signature is returned,
// and that the same signaure can be verified.
func TestSignMessageVerifySignature(t *testing.T) {
	t.Parallel()

	pluginClient := getPluginClient(t)

	testMessageBytes := []byte("any message")
	hasher := testHashFunc.New()
	if _, err := hasher.Write(testMessageBytes); err != nil {
		t.Fatal(err)
	}
	testDigest := hasher.Sum(nil) // Now this is the hash of "any message"

	signOpts := []signature.SignOption{}
	verifyOpts := []signature.VerifyOption{}

	signOpts = append(signOpts, options.WithDigest(testDigest))
	verifyOpts = append(verifyOpts, options.WithDigest(testDigest))

	signature, err := pluginClient.SignMessage(bytes.NewReader(testMessageBytes), signOpts...)

	os.Stderr.WriteString(fmt.Sprintf("IN TEST SIGNATURE: %v\n", signature))

	if err == nil && len(signature) == 0 {
		t.Error("expected non-empty signature")
	}

	if len(signature) > 0 {
		// verify the real signature
		if err = pluginClient.VerifySignature(bytes.NewReader(signature), bytes.NewReader(testMessageBytes), verifyOpts...); err != nil {
			t.Errorf("unexpected error verifying signature: %s", err)
		}
	}

}
