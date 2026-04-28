package bb

import (
	"testing"

	"bb-project/bb/model"
	chash "bb-project/cryptography/hash"
	"bb-project/cryptography/signature"
)

type testContext struct {
	scheme     signature.Scheme
	publicKey  []byte
	privateKey []byte
	hasher     chash.MerkleTreeHash
	log        *Log
	verifier   *Verifier
	entry      model.Entry
	receipt    Receipt
	proof      [][]byte
}

func setupTestContext(t *testing.T) testContext {
	t.Helper()

	baseHash := chash.SHA256Scheme{}
	merkleHasher := chash.MerkleTreeHash{
		BaseHash: baseHash,
	}

	publicKey, privateKey, err := signature.GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("failed to generate key pair: %v", err)
	}

	signer := signature.NewEd25519Signer(publicKey, privateKey)
	scheme := signature.Ed25519Scheme{}

	log := NewLog(merkleHasher, signer)
	verifier := NewVerifier(scheme, publicKey, merkleHasher)

	entry := model.Entry{
		EntryType:   "ballot",
		Context:     "test-election",
		Payload:     []byte("vote:Alice"),
		SubmitterID: []byte("voter-001"),
		Timestamp:   "2026-03-31T10:00:00Z",
	}

	receipt, err := log.Append(entry)
	if err != nil {
		t.Fatalf("failed to append entry: %v", err)
	}

	proof, err := log.InclusionProof(receipt.Index)
	if err != nil {
		t.Fatalf("failed to get inclusion proof: %v", err)
	}

	return testContext{
		scheme:     scheme,
		publicKey:  publicKey,
		privateKey: privateKey,
		hasher:     merkleHasher,
		log:        log,
		verifier:   verifier,
		entry:      entry,
		receipt:    receipt,
		proof:      proof,
	}
}

func cloneBytes(b []byte) []byte {
	if b == nil {
		return nil
	}
	out := make([]byte, len(b))
	copy(out, b)
	return out
}

func cloneProof(proof [][]byte) [][]byte {
	if proof == nil {
		return nil
	}
	out := make([][]byte, len(proof))
	for i := range proof {
		out[i] = cloneBytes(proof[i])
	}
	return out
}

func TestVerifyEntryInCheckpoint_Valid(t *testing.T) {
	tc := setupTestContext(t)

	ok, err := tc.verifier.VerifyEntryInCheckpoint(
		tc.entry,
		tc.receipt,
		tc.proof,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Fatal("expected verification to succeed")
	}
}

func TestVerifyEntryInCheckpoint_ModifiedEntry(t *testing.T) {
	tc := setupTestContext(t)

	modifiedEntry := tc.entry
	modifiedEntry.Payload = []byte("vote:Bob")

	ok, err := tc.verifier.VerifyEntryInCheckpoint(
		modifiedEntry,
		tc.receipt,
		tc.proof,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Fatal("expected verification to fail for modified entry")
	}
}

func TestVerifyEntryInCheckpoint_ModifiedProof(t *testing.T) {
	tc := setupTestContext(t)

	badProof := cloneProof(tc.proof)

	if len(badProof) == 0 {
		secondEntry := model.Entry{
			EntryType:   "ballot",
			Context:     "test-election",
			Payload:     []byte("vote:Charlie"),
			SubmitterID: []byte("voter-002"),
			Timestamp:   "2026-03-31T10:01:00Z",
		}

		_, err := tc.log.Append(secondEntry)
		if err != nil {
			t.Fatalf("failed to append second entry: %v", err)
		}

		var proofErr error
		badProof, proofErr = tc.log.InclusionProof(tc.receipt.Index)
		if proofErr != nil {
			t.Fatalf("failed to get updated inclusion proof: %v", proofErr)
		}

		newCheckpoint, cpErr := tc.log.Checkpoint()
		if cpErr != nil {
			t.Fatalf("failed to get updated checkpoint: %v", cpErr)
		}
		tc.receipt.Checkpoint = newCheckpoint
	}

	badProof[0][0] ^= 0xFF

	ok, err := tc.verifier.VerifyEntryInCheckpoint(
		tc.entry,
		tc.receipt,
		badProof,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Fatal("expected verification to fail for modified proof")
	}
}

func TestVerifyEntryInCheckpoint_ModifiedCheckpoint(t *testing.T) {
	tc := setupTestContext(t)

	badReceipt := tc.receipt
	badReceipt.Checkpoint.RootHash = cloneBytes(tc.receipt.Checkpoint.RootHash)
	badReceipt.Checkpoint.RootHash[0] ^= 0xFF

	ok, err := tc.verifier.VerifyEntryInCheckpoint(
		tc.entry,
		badReceipt,
		tc.proof,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Fatal("expected verification to fail for modified checkpoint")
	}
}

func TestVerifyEntryInCheckpoint_WrongPublicKey(t *testing.T) {
	tc := setupTestContext(t)

	wrongPublicKey, _, err := signature.GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("failed to generate wrong public key: %v", err)
	}

	wrongVerifier := NewVerifier(tc.scheme, wrongPublicKey, tc.hasher)

	ok, err := wrongVerifier.VerifyEntryInCheckpoint(
		tc.entry,
		tc.receipt,
		tc.proof,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Fatal("expected verification to fail with wrong public key")
	}
}

func TestVerifyEntryInCheckpoint_WrongIndex(t *testing.T) {
	tc := setupTestContext(t)

	secondEntry := model.Entry{
		EntryType:   "ballot",
		Context:     "test-election",
		Payload:     []byte("vote:Bob"),
		SubmitterID: []byte("voter-002"),
		Timestamp:   "2026-03-31T10:01:00Z",
	}

	_, err := tc.log.Append(secondEntry)
	if err != nil {
		t.Fatalf("failed to append second entry: %v", err)
	}

	proof, err := tc.log.InclusionProof(tc.receipt.Index)
	if err != nil {
		t.Fatalf("failed to get updated inclusion proof: %v", err)
	}

	cp, err := tc.log.Checkpoint()
	if err != nil {
		t.Fatalf("failed to get updated checkpoint: %v", err)
	}

	badReceipt := tc.receipt
	badReceipt.Index = tc.receipt.Index + 1
	badReceipt.Checkpoint = cp

	ok, err := tc.verifier.VerifyEntryInCheckpoint(
		tc.entry,
		badReceipt,
		proof,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Fatal("expected verification to fail with wrong index")
	}
}

// Per verificare EntryInCheckpoint: go test ./...
