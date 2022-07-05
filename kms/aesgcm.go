package kms

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
)

// AESGCM is a struct that contains a key of random bytes and additional
// information to re-use it in a safe way.
type AESGCM struct {
	key []byte

	aesgcm cipher.AEAD
}

// NewAESGCM returns a pointer to a AESGCM with a key and cipher.AEAD created.
func NewAESGCM() (*AESGCM, error) {
	key, err := randomBytes(keySize)
	if err != nil {
		return nil, err
	}

	return FromKey(key)
}

func FromKey(key []byte) (*AESGCM, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	return &AESGCM{
		key:    key,
		aesgcm: aesgcm,
	}, nil

}

// Key returns the internal Key used for encryption.
func (c *AESGCM) Key() []byte {
	return c.key
}

// Encrypt encrypts given plaintext. The nonce is prepended. Therefore any
// change to the standard nonceSize is a breaking change.
func (c *AESGCM) Encrypt(plaintext []byte) ([]byte, error) {
	nonce, err := randomBytes(nonceSize)
	if err != nil {
		return nil, err
	}

	return append(
		nonce,
		c.aesgcm.Seal(nil, nonce, plaintext, nil)...,
	), nil
}

// Decrypt decrypts a ciphertext. The nonce is assumed to be prepended.
// Therefore any change to the standard nonceSize is a breaking change.
func (k *AESGCM) Decrypt(ciphertext []byte) ([]byte, error) {
	plaintext, err := k.aesgcm.Open(
		nil,
		ciphertext[:nonceSize],
		ciphertext[nonceSize:],
		nil,
	)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// randomBytes generates length amount of bytes.
func randomBytes(length int) (key []byte, err error) {
	key = make([]byte, length)

	// TODO@ibihim: diff between rand.Read and ioutil.ReadFull?
	if _, err = rand.Read(key); err != nil {
		return nil, err
	}

	return key, nil
}
