package bb

import (
	chash "bb-project/cryptography/hash"
	"errors"
)

type MerkleTree struct {
	leaves [][]byte
	hasher chash.MerkleTreeHash
}

// NewMerkleTree creates a new merkle tree
func NewMerkleTree(hasher chash.MerkleTreeHash) *MerkleTree {
	return &MerkleTree{
		leaves: [][]byte{},
		hasher: hasher,
	}
}

// AddLeaf adds an already-hashed leaf to the Merkle tree.
func (m *MerkleTree) AddLeaf(leaf []byte) {
	c := make([]byte, len(leaf))
	copy(c, leaf)
	m.leaves = append(m.leaves, c)
}

// Leaves returns all leaves currently stored in the tree.
func (m *MerkleTree) Leaves() [][]byte {
	out := make([][]byte, len(m.leaves))
	for i, leaf := range m.leaves {
		c := make([]byte, len(leaf))
		copy(c, leaf)
		out[i] = c
	}
	return out
}

// Size returns the number of leaves in the tree.
func (m *MerkleTree) Size() int {
	return len(m.leaves)
}

// Root computes the current Merkle root.
// If the tree is empty, it returns nil.
func (m *MerkleTree) Root() []byte {
	if len(m.leaves) == 0 {
		return nil
	}

	// Work on a copy so we do not modify the original leaves slice.
	nodes := make([][]byte, len(m.leaves))
	copy(nodes, m.leaves)

	// we go up on the levels of the tree (loop untile there is one node -> the root)
	for len(nodes) > 1 {
		var nextLevel [][]byte

		for i := 0; i < len(nodes); i += 2 {
			if i+1 < len(nodes) {
				parent := m.hasher.HashNode(nodes[i], nodes[i+1])
				nextLevel = append(nextLevel, parent)
			} else {
				// Odd node: promote it to the next level.
				nextLevel = append(nextLevel, nodes[i])
			}
		}

		nodes = nextLevel
	}

	root := nodes[0]
	out := make([]byte, len(root))
	copy(out, root)
	return out
}

func (m *MerkleTree) InclusionProof(index int) ([][]byte, error) {
	if index < 0 || index >= len(m.leaves) {
		return nil, errors.New("invalid leaf index")
	}

	var proof [][]byte

	nodes := make([][]byte, len(m.leaves))
	copy(nodes, m.leaves)

	currentIndex := index

	for len(nodes) > 1 {
		if currentIndex%2 == 0 {
			if currentIndex+1 < len(nodes) {
				sibling := make([]byte, len(nodes[currentIndex+1]))
				copy(sibling, nodes[currentIndex+1])
				proof = append(proof, sibling)
			}
		} else {
			sibling := make([]byte, len(nodes[currentIndex-1]))
			copy(sibling, nodes[currentIndex-1])
			proof = append(proof, sibling)
		}

		var nextLevel [][]byte
		for i := 0; i < len(nodes); i += 2 {
			if i+1 < len(nodes) {
				parent := m.hasher.HashNode(nodes[i], nodes[i+1])
				nextLevel = append(nextLevel, parent)
			} else {
				nextLevel = append(nextLevel, nodes[i])
			}
		}

		nodes = nextLevel
		currentIndex /= 2
	}

	return proof, nil
}

func largestPowerOfTwoLessThan(a int) int {
	if a <= 1 {
		return 0
	}

	p := 1
	for p*2 < a {
		p *= 2
	}
	return p
}

func (m *MerkleTree) hashRange(start, end int) []byte {
	if start < 0 || end > len(m.leaves) || start >= end {
		return nil
	}

	nodes := make([][]byte, end-start)
	copy(nodes, m.leaves[start:end])

	for len(nodes) > 1 {
		var nextLevel [][]byte

		for i := 0; i < len(nodes); i += 2 {
			if i+1 < len(nodes) {
				parent := m.hasher.HashNode(nodes[i], nodes[i+1])
				nextLevel = append(nextLevel, parent)
			} else {
				nextLevel = append(nextLevel, nodes[i])
			}
		}

		nodes = nextLevel
	}

	out := make([]byte, len(nodes[0]))
	copy(out, nodes[0])
	return out
}

func (m *MerkleTree) subProof(start, oldSize, newSize int) [][]byte {
	if oldSize == newSize {
		return [][]byte{m.hashRange(start, start+newSize)}
	}

	k := largestPowerOfTwoLessThan(newSize)

	if oldSize <= k {
		proof := m.subProof(start, oldSize, k)
		rightHash := m.hashRange(start+k, start+newSize)
		proof = append(proof, rightHash)
		return proof
	}

	proof := m.subProof(start+k, oldSize-k, newSize-k)
	leftHash := m.hashRange(start, start+k)
	proof = append(proof, leftHash)
	return proof
}

func (m *MerkleTree) ConsistencyProof(oldSize, newSize int) ([][]byte, error) {
	if oldSize < 0 || newSize < 0 {
		return nil, errors.New("invalid tree size")
	}
	if oldSize > newSize {
		return nil, errors.New("old tree size cannot be greater than new tree size")
	}
	if newSize > len(m.leaves) {
		return nil, errors.New("new tree size exceeds number of leaves")
	}
	if oldSize == 0 {
		return [][]byte{}, nil
	}
	if oldSize == newSize {
		return [][]byte{}, nil
	}

	return m.subProof(0, oldSize, newSize), nil
}
