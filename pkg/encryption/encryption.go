package encryption

import (
	"context"
	"fmt"

	"github.com/aramase/kms/pkg/kek"
)

type EncryptionService interface {
	Decrypt(ctx context.Context, ciphertext, encKEK []byte) (plaintext []byte, err error)
	Encrypt(ctx context.Context, plaintext []byte) (ciphertext, encKEK []byte, err error)
}

type EncryptionHandler func(kek.KeyEncryptionKeyService) (EncryptionService, error)

var _ fmt.Stringer = EncryptionMode{}

type EncryptionMode struct {
	Name    string
	Version string
	Handler EncryptionHandler
}

func (e EncryptionMode) String() string {
	return e.Name
}
