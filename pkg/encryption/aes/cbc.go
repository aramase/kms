package aes

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"

	"github.com/aramase/kms/pkg/encryption"
	"github.com/aramase/kms/pkg/kek"
)

func NewAESCBCService(kek kek.KeyEncryptionKeyService) (encryption.EncryptionService, error) {
	c := &cbc{kek: kek}
	if _, _, err := c.getBlock(context.TODO(), nil); err != nil {
		return nil, err
	}
	return c, nil
}

var (
	errInvalidDataLength   = errors.New("the stored data was shorter than the required size")
	errInvalidBlockSize    = errors.New("the stored data is not a multiple of the block size")
	errInvalidPKCS7Data    = errors.New("invalid PKCS7 data (empty or not padded)")
	errInvalidPKCS7Padding = errors.New("invalid padding on input")
)

type cbc struct {
	kek kek.KeyEncryptionKeyService
}

func (c *cbc) Decrypt(ctx context.Context, ciphertext, encKEK []byte) ([]byte, error) {
	block, _, err := c.getBlock(ctx, encKEK)
	if err != nil {
		return nil, err
	}

	blockSize := aes.BlockSize
	if len(ciphertext) < blockSize {
		return nil, errInvalidDataLength
	}
	iv := ciphertext[:blockSize]
	ciphertext = ciphertext[blockSize:]

	if len(ciphertext)%blockSize != 0 {
		return nil, errInvalidBlockSize
	}

	result := make([]byte, len(ciphertext))
	copy(result, ciphertext)
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(result, result)

	// remove and verify PKCS#7 padding for CBC
	lastPadding := result[len(result)-1]
	paddingSize := int(lastPadding)
	size := len(result) - paddingSize
	if paddingSize == 0 || paddingSize > len(result) {
		return nil, errInvalidPKCS7Data
	}
	for i := 0; i < paddingSize; i++ {
		if result[size+i] != lastPadding {
			return nil, errInvalidPKCS7Padding
		}
	}

	return result[:size], nil
}

func (c *cbc) Encrypt(ctx context.Context, plaintext []byte) ([]byte, []byte, error) {
	block, encKey, err := c.getBlock(ctx, nil)
	if err != nil {
		return nil, nil, err
	}

	blockSize := aes.BlockSize
	paddingSize := blockSize - (len(plaintext) % blockSize)
	result := make([]byte, blockSize+len(plaintext)+paddingSize)
	iv := result[:blockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, nil, err
	}
	copy(result[blockSize:], plaintext)

	// add PKCS#7 padding for CBC
	copy(result[blockSize+len(plaintext):], bytes.Repeat([]byte{byte(paddingSize)}, paddingSize))

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(result[blockSize:], result[blockSize:])
	return result, encKey, nil
}

func (c *cbc) getBlock(ctx context.Context, encKEK []byte) (cipher.Block, []byte, error) {
	key, encKey, err := c.kek.Get(ctx, encKEK)
	if err != nil {
		return nil, nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}

	return block, encKey, nil
}
