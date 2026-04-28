package model

import (
	"crypto/sha256"
	"encoding/json"
)

type Ballot struct {
	ElectionID    string
	BallotID      string
	EncryptedVote string
	VoterProof    string
	Timestamp     int64
}

func (b *Ballot) Hash() ([]byte, error) {
	data, err := json.Marshal(b)
	if err != nil {
		return nil, err
	}
	hash := sha256.Sum256(data)
	return hash[:], nil
}
