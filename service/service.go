package service

import (
	"context"
	"encoding/base64"

	"k8s.io/klog/v2"

	"github.com/aramase/kms/kms"
	api "github.com/aramase/kms/v2alpha1"
)

const (
	version              = "v2alpha1"
	encryptedLocalKEKKey = "encryptedLocalKEK"
)

// Service offers encryption and decryption cache upfront of an upstream KMS.
type Service struct {
	managedKeys *kms.ManagedCipher
}

var (
	_ api.KeyManagementServiceServer = (*Service)(nil)
)

// NewKeyManagementService creates an v2alpha1.KeyManagementServiceServer that
// can be used for encryption and decryption, if given an upstream encryption
// service (upstream KMS).
func NewKeyManagementService(upstreamCipher kms.EncrypterDecrypter) (api.KeyManagementServiceServer, error) {
	mk, err := kms.NewManagedCipher(upstreamCipher)
	if err != nil {
		klog.Infof("create key management service: %w", err)
		return nil, err
	}

	klog.Infof("new key management service created")

	return &Service{
		managedKeys: mk,
	}, nil
}

// Status returns version data to verify the state of the service.
func (s *Service) Status(ctx context.Context, _ *api.StatusRequest) (*api.StatusResponse, error) {
	return &api.StatusResponse{
		Version: version,
		Healthz: "ok",
		KeyId:   base64.StdEncoding.EncodeToString(s.managedKeys.CurrentKeyID()),
	}, nil
}

// Decrypt decrypts the given request. If no encrypted local KEK is given in
// the metadata section, the assumption is that the ciphertext is being
// decrypted directly by the remote KMS.
// Returns the assumed current key id. It is being synced if the
// local kek is unknown or not given at all.
func (s *Service) Decrypt(ctx context.Context, req *api.DecryptRequest) (*api.DecryptResponse, error) {
	klog.Infof("decrypt request (id: %q) received", req.Uid)

	keyID, err := base64.StdEncoding.DecodeString(req.KeyId)
	if err != nil {
		klog.Infof("ObservedKeyID decode attempt failed for request (id: %q): %w", req.Uid, err)
		return nil, err
	}

	encryptedLocalKEK, ok := req.Annotations[encryptedLocalKEKKey]
	if ok {
		pt, err := s.managedKeys.Decrypt(keyID, encryptedLocalKEK, req.Ciphertext)
		if err != nil {
			klog.Infof("decrypt attempt (id: %q) failed: %w", req.Uid, err)
			return nil, err
		}

		klog.Infof("decrypt request (id: %q) succeeded", req.Uid)

		return &api.DecryptResponse{
			Plaintext: pt,
		}, nil
	}

	pt, err := s.managedKeys.DecryptRemotely(keyID, req.Ciphertext)
	if err != nil {
		klog.Infof("decrypt remotely (id: %q) failed: %w", req.Uid, err)
	}

	return &api.DecryptResponse{
		Plaintext: pt,
	}, nil
}

// Encrypt encrypts the given plaintext with the currently used local KEK. The
// currently used local KEK is returned in encrypted form to be communicated in
// the metadata section to enable seamless decryption.
// The encrypted KEK must be sent along a future decryption request to decrypt
// the returned ciphertext.
// Returns also the assumed current key id. It is synchronized on local kek
// rotation.
func (s *Service) Encrypt(ctx context.Context, req *api.EncryptRequest) (*api.EncryptResponse, error) {
	klog.Infof("encrypt request received (id: %q)", req.Uid)

	remoteKeyID, encryptedLocalKEK, ct, err := s.managedKeys.Encrypt(req.Plaintext)
	if err != nil {
		klog.Infof("encrypt attempt (id: %q) failed: %w", req.Uid, err)
		return nil, err
	}

	klog.Infof("encrypt request (id: %q) succeeded", req.Uid)

	return &api.EncryptResponse{
		KeyId:      base64.StdEncoding.EncodeToString(remoteKeyID),
		Ciphertext: ct,
		Annotations: map[string][]byte{
			encryptedLocalKEKKey: encryptedLocalKEK,
		},
	}, nil
}
