package main

import (
	"fmt"
	"os"

	infisical "github.com/infisical/sigstore-kms-infisical/internal"
	"github.com/sigstore/sigstore/pkg/signature/kms"
	"github.com/sigstore/sigstore/pkg/signature/kms/cliplugin/common"
	"github.com/sigstore/sigstore/pkg/signature/kms/cliplugin/handler"
)

const expectedProtocolVersion = common.ProtocolVersion

func newSignerVerifier(initOptions *common.InitOptions) (kms.SignerVerifier, error) {
	fullKeyResourceID := infisical.ReferenceScheme + initOptions.KeyResourceID
	return infisical.LoadSignerVerifier(fullKeyResourceID)
}

func main() {
	if protocolVersion := os.Args[1]; protocolVersion != expectedProtocolVersion {
		err := fmt.Errorf("expected protocol version: %s, got %s", expectedProtocolVersion, protocolVersion)
		_ = handler.WriteErrorResponse(os.Stdout, err)
		panicWithErr(err)
	}

	pluginArgs, err := handler.GetPluginArgs(os.Args)
	if err != nil {
		_ = handler.WriteErrorResponse(os.Stdout, err)
		panicWithErr(err)
	}

	signerVerifier, err := newSignerVerifier(pluginArgs.InitOptions)
	if err != nil {
		_ = handler.WriteErrorResponse(os.Stdout, err)
		panicWithErr(err)
	}

	_, err = handler.Dispatch(os.Stdout, os.Stdin, pluginArgs, signerVerifier)
	if err != nil {
		// Dispatch() will have already called WriteResponse() with the error.
		panicWithErr(err)
	}
}

func panicWithErr(err error) {
	panic(fmt.Errorf("%+v", err))
}
