package bb

import (
	"bb-project/bb/model"
	"bb-project/cryptography/hash"
	"bb-project/cryptography/signature"
	"bytes"
	"errors"
)

type Verifier struct {
	scheme    signature.Scheme
	publicKey []byte
	hasher    hash.MerkleTreeHash
}

func NewVerifier(
	scheme signature.Scheme,
	publicKey []byte,
	hasher hash.MerkleTreeHash,
) *Verifier {
	pkCopy := make([]byte, len(publicKey))
	copy(pkCopy, publicKey)

	return &Verifier{
		scheme:    scheme,
		publicKey: pkCopy,
		hasher:    hasher,
	}
}

func (v *Verifier) VerifyCheckpoint(cp Checkpoint) (bool, error) {
	data, err := cp.EncodeForSigning()
	if err != nil {
		return false, err
	}

	ok := v.scheme.Verify(v.publicKey, data, cp.Signature)
	return ok, nil
}

func (v *Verifier) VerifyInclusionProof(receipt Receipt, proof [][]byte) bool {
	if receipt.Index < 0 {
		return false
	}

	current := receipt.LeafHash
	currentIndex := receipt.Index

	for _, sibling := range proof {
		if currentIndex%2 == 0 {
			current = v.hasher.HashNode(current, sibling)
		} else {
			current = v.hasher.HashNode(sibling, current)
		}
		currentIndex /= 2
	}

	return bytes.Equal(current, receipt.Checkpoint.RootHash)
}

func (v *Verifier) VerifyConsistencyProof(oldCp, newCp Checkpoint, proof [][]byte) bool {
	oldSize := oldCp.TreeSize
	newSize := newCp.TreeSize
	oldRoot := oldCp.RootHash
	newRoot := newCp.RootHash

	if oldSize > newSize {
		return false
	}

	if oldSize == newSize {
		return bytes.Equal(oldRoot, newRoot)
	}

	if oldSize == 0 {
		return true
	}

	if len(proof) == 0 {
		return false
	}

	fn := oldSize - 1
	sn := newSize - 1

	for fn%2 == 1 {
		fn /= 2
		sn /= 2
	}

	fr := proof[0] //old root
	sr := proof[0] //new root

	for i := 1; i < len(proof); i++ {
		if fn%2 == 1 || fn == sn {
			fr = v.hasher.HashNode(proof[i], fr)
			sr = v.hasher.HashNode(proof[i], sr)
		} else {
			sr = v.hasher.HashNode(sr, proof[i])
		}

		fn /= 2
		sn /= 2
	}

	return bytes.Equal(fr, oldRoot) && bytes.Equal(sr, newRoot)
}

func (v *Verifier) VerifyEntryInCheckpoint(
	e model.Entry,
	receipt Receipt,
	proof [][]byte,
) (bool, error) {
	if receipt.Index < 0 {
		return false, errors.New("invalid index")
	}

	ok, err := v.VerifyCheckpoint(receipt.Checkpoint)
	if err != nil {
		return false, err
	}
	if !ok {
		return false, nil
	}

	data, err := e.EncodeForSigning()
	if err != nil {
		return false, err
	}

	leafHash := v.hasher.HashLeaf(data)

	if !bytes.Equal(leafHash, receipt.LeafHash) {
		return false, nil
	}

	proofOK := v.VerifyInclusionProof(receipt, proof)
	if !proofOK {
		return false, nil
	}

	return true, nil
}
