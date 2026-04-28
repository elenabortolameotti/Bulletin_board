package bb

import (
	"bb-project/bb/model"
	chash "bb-project/cryptography/hash"
	"bb-project/cryptography/signature"
	"encoding/hex"
	"errors"
)

type Receipt struct {
	Index      int        `json:"index"`
	LeafHash   []byte     `json:"leaf_hash"`
	Checkpoint Checkpoint `json:"checkpoint"`
}

func (r Receipt) EntryID() string {
	return hex.EncodeToString(r.LeafHash)
}

type Log struct {
	entries []model.Entry
	tree    *MerkleTree
	hasher  chash.MerkleTreeHash
	signer  signature.Signer
}

func NewLog(hasher chash.MerkleTreeHash, signer signature.Signer) *Log {
	return &Log{
		entries: make([]model.Entry, 0),
		tree:    NewMerkleTree(hasher),
		hasher:  hasher,
		signer:  signer,
	}
}

func (l *Log) Append(entry model.Entry) (Receipt, error) {
	entryBytes, err := entry.EncodeForSigning()
	if err != nil {
		return Receipt{}, err
	}

	leafHash := l.hasher.HashLeaf(entryBytes)

	l.tree.AddLeaf(leafHash)
	l.entries = append(l.entries, entry)

	checkpoint, err := l.Checkpoint()
	if err != nil {
		return Receipt{}, err
	}

	return Receipt{
		Index:      len(l.entries) - 1,
		LeafHash:   leafHash,
		Checkpoint: checkpoint,
	}, nil
}

func (l *Log) Root() []byte {
	root := l.tree.Root()
	out := make([]byte, len(root))
	copy(out, root)
	return out
}

func (l *Log) Size() int {
	return len(l.entries)
}

func (l *Log) Entries() []model.Entry {
	out := make([]model.Entry, len(l.entries))
	copy(out, l.entries)
	return out
}

func (l *Log) GetEntry(index int) (model.Entry, error) {
	if index < 0 || index >= len(l.entries) {
		return model.Entry{}, errors.New("invalid entry index")
	}
	return l.entries[index], nil
}

func (l *Log) InclusionProof(index int) ([][]byte, error) {
	return l.tree.InclusionProof(index)
}

func (l *Log) ConsistencyProof(oldSize, newSize int) ([][]byte, error) {
	return l.tree.ConsistencyProof(oldSize, newSize)
}
