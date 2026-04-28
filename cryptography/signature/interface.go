package signature

type Scheme interface {
	Sign(privateKey []byte, message []byte) ([]byte, error)
	Verify(publicKey []byte, message []byte, sig []byte) bool
	Name() string
}

type Signer interface {
	Sign(message []byte) ([]byte, error)
	PublicKey() []byte
}
