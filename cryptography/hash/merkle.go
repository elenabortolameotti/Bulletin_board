package hash

type MerkleTreeHash struct {
	BaseHash HashFunction
}

func (m MerkleTreeHash) Name() string {
	return "Merkle(" + m.BaseHash.Name() + ")"
}

func (m MerkleTreeHash) OutputSize() int {
	return m.BaseHash.OutputSize()
}

// HashLeaf(data) = H(0x00 || data)
func (m MerkleTreeHash) HashLeaf(data []byte) []byte {
	input := append([]byte{0x00}, data...)
	return m.BaseHash.Digest(input)
}

// HashNode(left, right) = H(0x01 || left || right)
func (m MerkleTreeHash) HashNode(left, right []byte) []byte {
	input := append([]byte{0x01}, left...)
	input = append(input, right...)
	return m.BaseHash.Digest(input)
}

// Perchè quei prefissi:
// Non puoi costruire alberi diversi con radice uguale
// La root rappresenta tutti i dati
// L'ordine è importante
// Inoltre, se ho due nodi X, Y e una foglia X||Y, se non mettiamo prefissi diversi
// la hash sarebbe la stessa
