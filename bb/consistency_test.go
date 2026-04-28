package bb

import (
	"testing"

	"bb-project/bb/model"
	chash "bb-project/cryptography/hash"
	"bb-project/cryptography/signature"
)

type consistencyTestContext struct {
	hasher   chash.MerkleTreeHash
	log      *Log
	verifier *Verifier
	cp1      Checkpoint
	cp2      Checkpoint
	cp3      Checkpoint
	cp4      Checkpoint
}

func setupConsistencyTestContext(t *testing.T) consistencyTestContext {
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
	log := NewLog(merkleHasher, signer)
	verifier := NewVerifier(signature.Ed25519Scheme{}, publicKey, merkleHasher)

	entry1 := model.Entry{
		EntryType:   "ballot",
		Context:     "test-election",
		Payload:     []byte("vote:Alice"),
		SubmitterID: []byte("voter-001"),
		Timestamp:   "2026-04-01T10:00:00Z",
	}
	entry2 := model.Entry{
		EntryType:   "ballot",
		Context:     "test-election",
		Payload:     []byte("vote:Bob"),
		SubmitterID: []byte("voter-002"),
		Timestamp:   "2026-04-01T10:01:00Z",
	}
	entry3 := model.Entry{
		EntryType:   "ballot",
		Context:     "test-election",
		Payload:     []byte("vote:Charlie"),
		SubmitterID: []byte("voter-003"),
		Timestamp:   "2026-04-01T10:02:00Z",
	}
	entry4 := model.Entry{
		EntryType:   "ballot",
		Context:     "test-election",
		Payload:     []byte("vote:Dave"),
		SubmitterID: []byte("voter-004"),
		Timestamp:   "2026-04-01T10:03:00Z",
	}

	_, err = log.Append(entry1)
	if err != nil {
		t.Fatalf("failed to append entry1: %v", err)
	}
	cp1, err := log.Checkpoint()
	if err != nil {
		t.Fatalf("failed to get checkpoint1: %v", err)
	}

	_, err = log.Append(entry2)
	if err != nil {
		t.Fatalf("failed to append entry2: %v", err)
	}
	cp2, err := log.Checkpoint()
	if err != nil {
		t.Fatalf("failed to get checkpoint2: %v", err)
	}

	_, err = log.Append(entry3)
	if err != nil {
		t.Fatalf("failed to append entry3: %v", err)
	}
	cp3, err := log.Checkpoint()
	if err != nil {
		t.Fatalf("failed to get checkpoint3: %v", err)
	}

	_, err = log.Append(entry4)
	if err != nil {
		t.Fatalf("failed to append entry4: %v", err)
	}
	cp4, err := log.Checkpoint()
	if err != nil {
		t.Fatalf("failed to get checkpoint4: %v", err)
	}

	return consistencyTestContext{
		hasher:   merkleHasher,
		log:      log,
		verifier: verifier,
		cp1:      cp1,
		cp2:      cp2,
		cp3:      cp3,
		cp4:      cp4,
	}
}

func cloneBytesForConsistency(b []byte) []byte {
	if b == nil {
		return nil
	}
	out := make([]byte, len(b))
	copy(out, b)
	return out
}

func cloneConsistencyProof(proof [][]byte) [][]byte {
	if proof == nil {
		return nil
	}
	out := make([][]byte, len(proof))
	for i := range proof {
		out[i] = cloneBytesForConsistency(proof[i])
	}
	return out
}

func TestVerifyConsistencyProof_Valid_1_To_3(t *testing.T) {
	tc := setupConsistencyTestContext(t)

	proof, err := tc.log.ConsistencyProof(1, 3)
	if err != nil {
		t.Fatalf("failed to get consistency proof: %v", err)
	}

	ok := tc.verifier.VerifyConsistencyProof(tc.cp1, tc.cp3, proof)
	if !ok {
		t.Fatal("expected consistency proof to be valid from checkpoint 1 to checkpoint 3")
	}
}

func TestVerifyConsistencyProof_Valid_2_To_4(t *testing.T) {
	tc := setupConsistencyTestContext(t)

	proof, err := tc.log.ConsistencyProof(2, 4)
	if err != nil {
		t.Fatalf("failed to get consistency proof: %v", err)
	}

	ok := tc.verifier.VerifyConsistencyProof(tc.cp2, tc.cp4, proof)
	if !ok {
		t.Fatal("expected consistency proof to be valid from checkpoint 2 to checkpoint 4")
	}
}

func TestVerifyConsistencyProof_SameTree(t *testing.T) {
	tc := setupConsistencyTestContext(t)

	proof, err := tc.log.ConsistencyProof(3, 3)
	if err != nil {
		t.Fatalf("failed to get consistency proof: %v", err)
	}

	ok := tc.verifier.VerifyConsistencyProof(tc.cp3, tc.cp3, proof)
	if !ok {
		t.Fatal("expected consistency proof to be valid for identical checkpoints")
	}
}

func TestVerifyConsistencyProof_EmptyOldTree(t *testing.T) {
	tc := setupConsistencyTestContext(t)

	proof, err := tc.log.ConsistencyProof(0, 3)
	if err != nil {
		t.Fatalf("failed to get consistency proof: %v", err)
	}

	emptyCp := Checkpoint{
		TreeSize: 0,
		RootHash: nil,
	}

	ok := tc.verifier.VerifyConsistencyProof(emptyCp, tc.cp3, proof)
	if !ok {
		t.Fatal("expected consistency proof to be valid from empty tree")
	}
}

func TestConsistencyProof_InvalidSizes(t *testing.T) {
	tc := setupConsistencyTestContext(t)

	_, err := tc.log.ConsistencyProof(4, 2)
	if err == nil {
		t.Fatal("expected error when oldSize > newSize")
	}
}

func TestVerifyConsistencyProof_InvalidSizes(t *testing.T) {
	tc := setupConsistencyTestContext(t)

	ok := tc.verifier.VerifyConsistencyProof(tc.cp4, tc.cp2, nil)
	if ok {
		t.Fatal("expected verification to fail when oldSize > newSize")
	}
}

func TestVerifyConsistencyProof_ModifiedProof(t *testing.T) {
	tc := setupConsistencyTestContext(t)

	proof, err := tc.log.ConsistencyProof(1, 4)
	if err != nil {
		t.Fatalf("failed to get consistency proof: %v", err)
	}

	badProof := cloneConsistencyProof(proof)
	if len(badProof) == 0 {
		t.Fatal("expected non-empty proof for 1 -> 4")
	}
	badProof[0][0] ^= 0xFF

	ok := tc.verifier.VerifyConsistencyProof(tc.cp1, tc.cp4, badProof)
	if ok {
		t.Fatal("expected verification to fail for modified proof")
	}
}

func TestVerifyConsistencyProof_ModifiedOldRoot(t *testing.T) {
	tc := setupConsistencyTestContext(t)

	proof, err := tc.log.ConsistencyProof(1, 4)
	if err != nil {
		t.Fatalf("failed to get consistency proof: %v", err)
	}

	badOldCp := tc.cp1
	badOldCp.RootHash = cloneBytesForConsistency(tc.cp1.RootHash)
	badOldCp.RootHash[0] ^= 0xFF

	ok := tc.verifier.VerifyConsistencyProof(badOldCp, tc.cp4, proof)
	if ok {
		t.Fatal("expected verification to fail for modified old root")
	}
}

func TestVerifyConsistencyProof_ModifiedNewRoot(t *testing.T) {
	tc := setupConsistencyTestContext(t)

	proof, err := tc.log.ConsistencyProof(1, 4)
	if err != nil {
		t.Fatalf("failed to get consistency proof: %v", err)
	}

	badNewCp := tc.cp4
	badNewCp.RootHash = cloneBytesForConsistency(tc.cp4.RootHash)
	badNewCp.RootHash[0] ^= 0xFF

	ok := tc.verifier.VerifyConsistencyProof(tc.cp1, badNewCp, proof)
	if ok {
		t.Fatal("expected verification to fail for modified new root")
	}
}

// Per verificare ConsistencyProof: go test ./bb -run Consistency -v
