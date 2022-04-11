package kms

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"sync"
	"time"

	"k8s.io/klog/v2"
)

const (
	// CollisionTolerance with 2^21 as a very defensive value. 2^32 is more commonly used.
	CollisionTolerance = 2097151
	// keySize is the key size in bytes
	keySize = 128 / 8
	// nonceSize is the size of the nonce. Do not change, without breaking version change.
	// The nonceSize is a de facto standard.
	nonceSize = 12
	// cacheSize is set to 100 keys, which can be used to decrypt up to 200 million encrypted
	// files or data encrypted within nearly 2 years.
	cacheSize = 100
)

var (
	// ErrKeyExpired means that the expiration time of a key has come and it shouldn't be used any more.
	ErrKeyExpired = errors.New("key is out of date and shouldn't be used anymore for encryption")
	// ErrNoCipher means that there is no upstream kms given and therefore the keys in use can't be protected.
	ErrNoCipher = errors.New("no upstream encryption service was specified")

	// expirationTime of a Week
	expirationTime = time.Hour * 24 * 7
)

// ManagedCipher is a set of keys. Only one key is used for encryption at one
// time. New keys are created automatically, when hitting safety thresholds.
type ManagedCipher struct {
	counter uint32
	expires time.Time

	keys            *cache
	currentLocalKEK []byte

	remoteKMSID    []byte
	upstreamCipher EncrypterDecrypter

	m sync.Mutex
}

// EncrypterDecrypter is a default encryption / decryption interface with an ID
// to support remote state.
type EncrypterDecrypter interface {
	Encrypt(plainKey []byte) (currentKeyID, encryptedKey []byte, err error)
	Decrypt(observedID, encryptedKey []byte) (currentKeyID, plainKey []byte, err error)
}

// CurrentKeyID returns the currently assumed remote Key ID.
func (m *ManagedCipher) CurrentKeyID() []byte {
	return m.remoteKMSID
}

// NewManagedCipher returns a pointer to a ManagedCipher. It is initialized with
// a cache, a reference to an upstream cipher (like a KMS service or HMS) and
// does an initial encryption call to the upstream cipher.
func NewManagedCipher(upstreamCipher EncrypterDecrypter) (*ManagedCipher, error) {
	if upstreamCipher == nil {
		klog.Infof("create managed cipher without upstream encryption failed")
		return nil, ErrNoCipher
	}

	mk := ManagedCipher{
		keys:           newCache(cacheSize),
		upstreamCipher: upstreamCipher,
	}

	if err := mk.manageKey(); err != nil {
		klog.Infof("create managed cipher: %w", err)
		return nil, err
	}

	klog.Infof("new managed cipher is created")

	return &mk, nil
}

func (m *ManagedCipher) manageKey() error {
	m.m.Lock()
	defer m.m.Unlock()

	m.counter = m.counter + 1

	if m.counter < CollisionTolerance && time.Now().Before(m.expires) {
		return nil
	}

	cipher, err := NewAESGCM()
	if err != nil {
		klog.Infof("create new cipher: %w", err)
		return err
	}

	remoteID, encKey, err := m.upstreamCipher.Encrypt(cipher.Key())
	if err != nil {
		klog.Infof("encrypt with upstream: %w", err)
		return err
	}

	m.keys.Add(encKey, cipher)
	m.currentLocalKEK = encKey
	m.remoteKMSID = remoteID
	m.expires = time.Now().Add(expirationTime)
	m.counter = 0

	klog.Infof("created key successfully and added to set")

	return nil
}

// Encrypt encrypts given plaintext and returns the key used in encrypted form.
// The encrypted key is encrypted by the given upstream KMS.
func (m *ManagedCipher) Encrypt(pt []byte) ([]byte, []byte, []byte, error) {
	if err := m.manageKey(); err != nil {
		return nil, nil, nil, fmt.Errorf("manage keys upfront of an encryption: %w", err)
	}

	cipher, ok := m.keys.Get(m.currentLocalKEK)
	if !ok {
		klog.Infof(
			"key (%q) has no value in cache",
			base64.StdEncoding.EncodeToString(m.currentLocalKEK),
		)
		return nil, nil, nil, fmt.Errorf(
			"unknown key (%q)",
			base64.StdEncoding.EncodeToString(m.currentLocalKEK),
		)
	}

	ct, err := cipher.Encrypt(pt)
	if err != nil {
		klog.Infof("encrypt plaintext: %w", err)
		return nil, nil, nil, err
	}

	return m.remoteKMSID, m.currentLocalKEK, ct, nil
}

// DecryptRemotely decrypts given ciphertext by sendin it directly to the
// remote kms.
func (m *ManagedCipher) DecryptRemotely(id, ct []byte) ([]byte, []byte, error) {
	return m.upstreamCipher.Decrypt(id, ct)
}

// Decrypt decrypts the given ciphertext. If the given encrypted key is unknown,
// KMS upstream is asked for decryption of the encrypted key.
func (m *ManagedCipher) Decrypt(observedKeyID, encKey, ct []byte) ([]byte, []byte, []byte, error) {
	cipher, ok := m.keys.Get(encKey)
	if ok {
		pt, err := cipher.Decrypt(ct)
		if err != nil {
			klog.Infof("decrypt ciphertext: %w", err)
			return nil, nil, nil, err
		}

		return m.remoteKMSID, encKey, pt, nil
	}

	klog.Infof(
		"key (%q) has no value in cache",
		base64.StdEncoding.EncodeToString(encKey),
	)

	// plainKey is a plaintext key and should be handled cautiously.
	remoteKeyID, plainKey, err := m.upstreamCipher.Decrypt(observedKeyID, encKey)
	if err != nil {
		klog.Infof(
			"decrypt key (%q) by upstream:",
			base64.StdEncoding.EncodeToString(encKey),
			err,
		)

		return nil, nil, nil, err
	}

	if !bytes.Equal(m.remoteKMSID, remoteKeyID) {
		m.m.Lock()
		m.remoteKMSID = remoteKeyID
		m.m.Unlock()
	}

	cipher, err = FromKey(plainKey)
	if err != nil {
		klog.Infof(
			"use key (%q) for encryption: %w",
			base64.StdEncoding.EncodeToString(encKey),
			err,
		)
		return nil, nil, nil, err
	}

	m.keys.Add(encKey, cipher)

	klog.Infof(
		"key (%q) from ciphertext added to cache",
		base64.StdEncoding.EncodeToString(encKey),
	)

	pt, err := cipher.Decrypt(ct)
	if err != nil {
		klog.Infof("decrypt ciphertext: %w", err)
		return nil, nil, nil, err
	}

	return m.remoteKMSID, encKey, pt, nil
}