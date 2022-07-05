package kms_test

import (
	"bytes"
	"encoding/base64"
	"sync"
	"testing"

	"github.com/aramase/kms/kms"
)

func TestManagedCipher(t *testing.T) {
	var id, encryptedLocalKEK, ct []byte
	plaintext := []byte("lorem ipsum")
	remoteKMS, err := newUpstreamKMS([]byte("helloworld"))
	if err != nil {
		t.Fatal(err)
	}

	t.Run("encrypt with ManagedCipher", func(t *testing.T) {
		mc, err := kms.NewManagedCipher(remoteKMS)
		if err != nil {
			t.Fatal(err)
		}

		_, encryptedLocalKEK, ct, err = mc.Encrypt(plaintext)
		if err != nil {
			t.Fatal(err)
		}

		pt, err := mc.Decrypt(id, encryptedLocalKEK, ct)
		if err != nil {
			t.Fatal(err)
		}

		if !bytes.Equal(pt, plaintext) {
			t.Fatalf(
				"want: %q,\nhave %q",
				plaintext, pt,
			)
		}
	})

	t.Run("decrypt with another ManagedCipher", func(t *testing.T) {
		mc, err := kms.NewManagedCipher(remoteKMS)
		if err != nil {
			t.Fatal(err)
		}

		pt, err := mc.Decrypt(id, encryptedLocalKEK, ct)
		if err != nil {
			t.Fatal(err)
		}

		if !bytes.Equal(pt, plaintext) {
			t.Fatalf(
				"want: %q,\nhave %q",
				plaintext, pt,
			)
		}
	})
}

func TestExpiry(t *testing.T) {
	remoteKMS, err := newUpstreamKMS([]byte("helloworld"))
	if err != nil {
		t.Fatal(err)
	}

	mc, err := kms.NewManagedCipher(remoteKMS)
	if err != nil {
		t.Fatal(err)
	}

	ids := make(map[string]struct{})
	plaintext := []byte("lorem ipsum")

	beyondCollision := kms.CollisionTolerance + 5
	var wg sync.WaitGroup
	var m safeMap

	// this might take a couple of seconds
	for i := 0; i < beyondCollision; i++ {
		wg.Add(1)

		go func(t *testing.T, ids map[string]struct{}) {
			defer wg.Done()

			_, encKey, _, err := mc.Encrypt(plaintext)
			if err != nil {
				t.Error(err)
			}

			id := base64.StdEncoding.EncodeToString(encKey)
			m.Add(id)
		}(t, ids)
	}

	wg.Wait()

	if m.Len() != 2 {
		t.Errorf("Expected 2 encrypted keys, have: %d", len(ids))
	}
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

func (k *remoteKMS) Decrypt(observedID, encryptedKey []byte) ([]byte, error) {
	pt, err := k.cipher.Decrypt(encryptedKey)
	if err != nil {
		return nil, err
	}

	return pt, nil
}

type safeMap struct {
	ma map[string]struct{}
	mu sync.Mutex
}

func (m *safeMap) Add(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.ma == nil {
		m.ma = make(map[string]struct{})
	}

	m.ma[id] = struct{}{}
}

func (m *safeMap) Len() int {
	return len(m.ma)
}
