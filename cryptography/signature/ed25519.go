package signature

import (
	"crypto/ed25519"
	"errors"
)

type Ed25519Scheme struct{}

func (s Ed25519Scheme) Name() string {
	return "Ed25519"
}

func (s Ed25519Scheme) Sign(privateKey []byte, message []byte) ([]byte, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, errors.New("invalid Ed25519 private key length")
	}

	sig := ed25519.Sign(ed25519.PrivateKey(privateKey), message)
	return sig, nil
}

func (s Ed25519Scheme) Verify(publicKey []byte, message []byte, sig []byte) bool {
	if len(publicKey) != ed25519.PublicKeySize {
		return false
	}

	if len(sig) != ed25519.SignatureSize {
		return false
	}

	return ed25519.Verify(ed25519.PublicKey(publicKey), message, sig)
}

func GenerateEd25519KeyPair() (publicKey []byte, privateKey []byte, err error) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, nil, err
	}

	return []byte(pub), []byte(priv), nil
}

type Ed25519Signer struct {
	privateKey []byte
	publicKey  []byte
	scheme     Ed25519Scheme
}

func NewEd25519Signer(publicKey, privateKey []byte) *Ed25519Signer {
	return &Ed25519Signer{
		privateKey: privateKey,
		publicKey:  publicKey,
		scheme:     Ed25519Scheme{},
	}
}

func (s *Ed25519Signer) Sign(message []byte) ([]byte, error) {
	return s.scheme.Sign(s.privateKey, message)
}

func (s *Ed25519Signer) PublicKey() []byte {
	return s.publicKey
}
