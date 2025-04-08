package main

import (
	"fmt"
	"os"

	"github.com/davecgh/go-spew/spew"
	"github.com/sigstore/sigstore/pkg/signature/kms/cliplugin/handler"
)

// See cliplugin.common.ProtocolVersion
const expectedProtocolVersion = "v1"

func main() {
	// we log to stderr, not stdout. stdout is reserved for the plugin return value.
	spew.Fdump(os.Stderr, os.Args)
	if protocolVersion := os.Args[1]; protocolVersion != expectedProtocolVersion {
		err := fmt.Errorf("expected protocol version: %s, got %s", expectedProtocolVersion, protocolVersion)
		handler.WriteErrorResponse(os.Stdout, err)
		panic(err)
	}

	pluginArgs, err := handler.GetPluginArgs(os.Args)
	if err != nil {
		handler.WriteErrorResponse(os.Stdout, err)
		panic(err)
	}
	spew.Fdump(os.Stderr, pluginArgs)

	signerVerifier := &VenafiSignerVerifier{
		hashFunc:      pluginArgs.InitOptions.HashFunc,
		keyResourceID: pluginArgs.InitOptions.KeyResourceID,
	}

	resp, err := handler.Dispatch(os.Stdout, os.Stdin, pluginArgs, signerVerifier)
	if err != nil {
		// Dispatch() will have already called WriteResponse() with the error.
		panic(err)
	}
	spew.Fdump(os.Stderr, resp)
}
