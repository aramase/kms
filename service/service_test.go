package service_test

import (
	"bytes"
	"context"
	"testing"

	"github.com/aramase/kms/kms"
	"github.com/aramase/kms/service"

	api "github.com/aramase/kms/v2alpha1"
)

func TestService(t *testing.T) {
	kms, err := newUpstreamKMS([]byte("hello world"))
	if err != nil {
		t.Fatal(err)
	}

	svc, err := service.NewKeyManagementService(kms)
	if err != nil {
		t.Fatal(err)
	}

	var ciphertext []byte
	var ciphertextMetadata map[string]string

	plaintext := []byte("lorem ipsum")
	version := "something"
	t.Run("encryption and decryption", func(t *testing.T) {

		encryptResponse, err := svc.Encrypt(context.TODO(), &api.EncryptRequest{
			Version: version,
			Plain:   plaintext,
			Uid:     "123",
		})
		if err != nil {
			t.Fatal(err)
		}

		decryptResponse, err := svc.Decrypt(context.TODO(), &api.DecryptRequest{
			Version:  version,
			Cipher:   encryptResponse.Cipher,
			Uid:      "456",
			Metadata: encryptResponse.Metadata,
		})
		if err != nil {
			t.Fatal(err)
		}

		if !bytes.Equal(plaintext, decryptResponse.Plain) {
			t.Fatalf(
				"want: %s, have: %s",
				string(plaintext), string(decryptResponse.Plain),
			)
		}

		ciphertext = encryptResponse.Cipher
		ciphertextMetadata = encryptResponse.Metadata
	})

	t.Run("decrypt by other kms plugin", func(t *testing.T) {
		anotherSvc, err := service.NewKeyManagementService(kms)
		if err != nil {
			t.Fatal(err)
		}

		decryptResponse, err := anotherSvc.Decrypt(context.TODO(), &api.DecryptRequest{
			Version:  version,
			Cipher:   ciphertext,
			Uid:      "789",
			Metadata: ciphertextMetadata,
		})
		if err != nil {
			t.Fatal(err)
		}

		if !bytes.Equal(plaintext, decryptResponse.Plain) {
			t.Errorf(
				"want: %s, have: %s",
				string(plaintext), string(decryptResponse.Plain),
			)
		}
	})

	t.Run("decrypt by remote kms", func(t *testing.T) {
		_, ct, err := kms.Encrypt(plaintext)
		if err != nil {
			t.Fatal(err)
		}

		svc.Decrypt(context.TODO(), &api.DecryptRequest{
			Cipher: ct,
			Uid:    "135",
		})
	})

	t.Run("status check", func(t *testing.T) {

	})
}

type remoteKMS struct {
	currentKeyID []byte
	cipher       *kms.AESGCM
}

func newUpstreamKMS(id []byte) (*remoteKMS, error) {
	cipher, err := kms.NewAESGCM()
	if err != nil {
		return nil, err
	}

	return &remoteKMS{
		cipher:       cipher,
		currentKeyID: id,
	}, nil
}

func (k *remoteKMS) Encrypt(pt []byte) ([]byte, []byte, error) {
	ct, err := k.cipher.Encrypt(pt)
	if err != nil {
		return nil, nil, err
	}

	return k.currentKeyID, ct, nil
}

func (k *remoteKMS) Decrypt(observedID, encryptedKey []byte) ([]byte, []byte, error) {
	pt, err := k.cipher.Decrypt(encryptedKey)
	if err != nil {
		return nil, nil, err
	}

	return k.currentKeyID, pt, nil
}