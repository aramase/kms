package kms_test

import (
	"bytes"
	"testing"

	"github.com/aramase/kms/kms"
)

func TestAESGCM(t *testing.T) {
	aesgcmNew, err := kms.NewAESGCM()
	if err != nil {
		t.Fatal(err)
	}

	plaintext := []byte("lorem ipsum")
	ciphertext, err := aesgcmNew.Encrypt(plaintext)
	if err != nil {
		t.Fatal(err)
	}

	decrypted, err := aesgcmNew.Decrypt(ciphertext)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Fatalf(
			"want: %q,\nhave: %q", plaintext, decrypted,
		)
	}

	aesgcmOld, err := kms.FromKey(aesgcmNew.Key())
	if err != nil {
		t.Fatal(err)
	}

	ciphertextAgain, err := aesgcmOld.Encrypt(plaintext)
	if err != nil {
		t.Fatal(err)
	}

	decryptedAgain, err := aesgcmNew.Decrypt(ciphertextAgain)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(plaintext, decryptedAgain) {
		t.Fatalf(
			"want: %q,\nhave: %q", plaintext, decrypted,
		)
	}

}
