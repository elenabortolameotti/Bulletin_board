package hash

type HashFunction interface {
	Digest(data []byte) []byte
	Name() string
	OutputSize() int
}

type MerkleFunction interface {
	HashLeaf(data []byte) []byte
	HashNode(left, right []byte) []byte
	Name() string
	OutputSize() int
}
