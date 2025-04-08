package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"

	infisical "github.com/infisical/sigstore-kms-infisical/internal"
	"github.com/sigstore/sigstore/pkg/signature"
)

type InfisicalSuite struct {
	suite.Suite
	projectId string
}

var cryptoHash = crypto.SHA512

func (suite *InfisicalSuite) GetProvider(key string, opts ...signature.RPCOption) *infisical.SignerVerifier {
	provider, err := infisical.LoadSignerVerifier(fmt.Sprintf("infisicalkms://%s", key))
	require.NoError(suite.T(), err)
	require.NotNil(suite.T(), provider)
	return provider
}

func (suite *InfisicalSuite) TestProvider() {
	suite.GetProvider("provider")
}

func (suite *InfisicalSuite) SetupSuite() {
	suite.projectId = os.Getenv("INFISICAL_PROJECT_ID")
}

func (suite *InfisicalSuite) TestEcdsaSignVerify() {
	provider := suite.GetProvider("test-ecc")

	pub, err := provider.PublicKey()
	assert.Nil(suite.T(), err)
	assert.NotNil(suite.T(), pub)

	data := []byte("mydata")
	sig, err := provider.SignMessage(bytes.NewReader(data))
	assert.Nil(suite.T(), err)
	assert.NotNil(suite.T(), sig)

	verifier, _ := signature.LoadECDSAVerifier(pub.(*ecdsa.PublicKey), cryptoHash)

	err = verifier.VerifySignature(bytes.NewReader(sig), bytes.NewReader(data))
	assert.Nil(suite.T(), err)
}

// func (suite *InfisicalSuite) TestRsaSignVerify() {
// 	provider := suite.GetProvider("test-rsa")

// 	pub, err := provider.PublicKey()

// 	assert.Nil(suite.T(), err)
// 	assert.NotNil(suite.T(), pub)

// 	data := []byte("mydata")
// 	sig, err := provider.SignMessage(bytes.NewReader(data))
// 	if err != nil {
// 		panic(err)
// 	}

// 	verifier, _ := signature.LoadRSAPKCS1v15Verifier(pub.(*rsa.PublicKey), cryptoHash)

// 	err = verifier.VerifySignature(bytes.NewReader(sig), bytes.NewReader(data))

// 	assert.Nil(suite.T(), err)
// }

func (suite *InfisicalSuite) TestCreateRsaKey() {
	provider := suite.GetProvider("test-rsa-new")

	pub, err := provider.CreateKey(context.Background(), "RSA_4096")
	assert.Nil(suite.T(), err)
	assert.NotNil(suite.T(), pub)

	fmt.Printf("Public key: %v\n", pub)
}

func (suite *InfisicalSuite) TestCreateEccKey() {
	provider := suite.GetProvider("test-ecc-new")

	pub, err := provider.CreateKey(context.Background(), "ECC_NIST_P256")
	assert.Nil(suite.T(), err)
	assert.NotNil(suite.T(), pub)
}

// func (suite *InfisicalSuite) TestVerifyInvalidRsaSignature() {
// 	provider := suite.GetProvider("test-rsa")

// 	pub, err := provider.PublicKey()
// 	assert.Nil(suite.T(), err)
// 	assert.NotNil(suite.T(), pub)

// 	data1 := []byte("mydata1")
// 	data2 := []byte("mydata2")

// 	sig1, err := provider.SignMessage(bytes.NewReader(data1))
// 	assert.Nil(suite.T(), err)
// 	assert.NotNil(suite.T(), sig1)

// 	verifier, _ := signature.LoadRSAPKCS1v15Verifier(pub.(*rsa.PublicKey), cryptoHash)

// 	err = verifier.VerifySignature(bytes.NewReader(sig1), bytes.NewReader(data2))
// 	assert.NotNil(suite.T(), err)
// }

func (suite *InfisicalSuite) TestVerifyInvalidEccSignature() {
	provider := suite.GetProvider("test-ecc")

	pub, err := provider.PublicKey()
	assert.Nil(suite.T(), err)
	assert.NotNil(suite.T(), pub)

	data1 := []byte("mydata1")
	data2 := []byte("mydata2")

	sig1, err := provider.SignMessage(bytes.NewReader(data1))
	assert.Nil(suite.T(), err)
	assert.NotNil(suite.T(), sig1)

	verifier, _ := signature.LoadECDSAVerifier(pub.(*ecdsa.PublicKey), cryptoHash)

	err = verifier.VerifySignature(bytes.NewReader(sig1), bytes.NewReader(data2))
	assert.NotNil(suite.T(), err)
}

func (suite *InfisicalSuite) TestCreateKeyWithInvalidAlgorithm() {
	provider := suite.GetProvider("test-ecc")

	pub, err := provider.CreateKey(context.Background(), "INVALID_ALGORITHM")
	assert.NotNil(suite.T(), err)
	assert.Nil(suite.T(), pub)
}

func TestInfisical(t *testing.T) {
	suite.Run(t, new(InfisicalSuite))
}
