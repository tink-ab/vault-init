package keystore

import (
	"fmt"
	"runtime"

	"github.com/hashicorp/vault/api"
)

var (
	UserAgent      = fmt.Sprintf("vault-init/0.5.0 (%s)", runtime.Version())
	unsealKeysFile = "vault/unseal-keys.json"
	rootTokenFile  = "vault/root-token"
)

// UnsealData contains only the keys needed for auto-unseal, without the root token.
type UnsealData struct {
	Keys    []string `json:"keys"`
	KeysB64 []string `json:"keys_base64"`
}

type Keystore interface {
	Close()
	EncryptAndWrite(*api.InitResponse) error
	ReadAndDecrypt() (*api.InitResponse, error)
}
