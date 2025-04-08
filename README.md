# sigstore-kms-infisical
Sigstore [KMS Plugin](https://github.com/sigstore/sigstore/tree/main/pkg/signature/kms/cliplugin) for Infisical

Supports [cosign](https://github.com/sigstore/cosign) image and artifact signing with [Infisical KMS](https://infisical.com/docs/documentation/platform/kms/overview), using the [Infisical Go SDK](https://github.com/infisical/go-sdk)

### KMS Plugin Spec Compatibility
| Capability | Compatibility |
| ---------- | ------------- |
| DefaultAlgorithm | RSA_4096 |
| SupportedAlgorithsm | RSA_4096, ECC_NIST_P256 |
| CreateKey | :x: |
| PublicKey | :heavy_check_mark: |
| SignMessage | :heavy_check_mark: |
| VerfiyMessage | :heavy_check_mark: |
| CryptoSigner | :x: |

### Installation

For the sigstore library to invoke the plugin, the binary must be in your system's PATH.

```sh
git clone https://github.com/Infisical/sigstore-kms-infisical.git
cd sigstore-kms-infisical
go build -o sigstore-kms-infisical
cp sigstore-kms-infisical /usr/local/bin
```

### Configuration

The Infisical KMS plugin relies on environment variables, and therefore must be set prior to running cosign with the plugin. Currently the plugin only support Machine Identity Universal Auth for authentication. More authentication methods will be added in the future.

#### Create Environment Variables

These are the minimum variables required

```bash
INFISICAL_SITE_URL="https://app.infisical.com"
INFISICAL_UNIVERSAL_AUTH_CLIENT_ID="<machine-identity-client-id>"
INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET="<machine-identity-client-id>"
INFISICAL_PROJECT_ID="<infisical-kms-project-id>"
```

### Signing a Container Image

```sh
cosign sign --key "infisical://{KMS_KEY_NAME}" --tlog-upload=false my-repo/image:v1
```

### Verifying a Container Image

```sh
cosign verify --key "infisical://{KMS_KEY_NAME}" --insecure-ignore-tlog=true my-repo/image:v1
```

### Creating a new keypair
```sh
cosign generate-key-pair --kms infisical://{NEW_KEY_TO_BE_CREATED}
```

The above will create an RSA 4096 KMS key with name `NEW_KEY_TO_BE_CREATED`, which you can then subsequently use to sign and verify with.