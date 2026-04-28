package hash

import (
	"crypto/sha256"
)

type SHA256Scheme struct{}

func (s SHA256Scheme) Name() string {
	return "sha256"
}

func (s SHA256Scheme) Digest(data []byte) []byte {
	h := sha256.Sum256(data)
	return h[:]
}

func (s SHA256Scheme) OutputSize() int {
	return sha256.Size
}
