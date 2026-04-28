package bb

import (
	"testing"

	"bb-project/bb/model"
	chash "bb-project/cryptography/hash"
	"bb-project/cryptography/signature"
)

type witnessTestContext struct {
	log       *Log
	witness   *Witness
	hasher    chash.MerkleTreeHash
	logPubKey []byte
	wPubKey   []byte
	wScheme   signature.Scheme
}

func setupWitnessTestContext(t *testing.T) witnessTestContext {
	t.Helper()

	baseHash := chash.SHA256Scheme{}
	hasher := chash.MerkleTreeHash{BaseHash: baseHash}

	// log keys
	logPub, logPriv, err := signature.GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("failed to generate log keys: %v", err)
	}
	logSigner := signature.NewEd25519Signer(logPub, logPriv)

	// witness keys
	wPub, wPriv, err := signature.GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("failed to generate witness keys: %v", err)
	}
	wSigner := signature.NewEd25519Signer(wPub, wPriv)

	log := NewLog(hasher, logSigner)

	w := NewWitness(
		wSigner,
		signature.Ed25519Scheme{},
		logPub,
		hasher,
	)

	return witnessTestContext{
		log:       log,
		witness:   w,
		hasher:    hasher,
		logPubKey: logPub,
		wPubKey:   wPub,
		wScheme:   signature.Ed25519Scheme{},
	}
}

func appendEntry(t *testing.T, log *Log, payload string) {
	t.Helper()

	e := model.Entry{
		EntryType:   "test",
		Context:     "ctx",
		Payload:     []byte(payload),
		SubmitterID: []byte("user"),
		Timestamp:   "now",
	}

	_, err := log.Append(e)
	if err != nil {
		t.Fatalf("append failed: %v", err)
	}
}

// TEST 1 — primo checkpoint
func TestWitness_FirstCheckpoint(t *testing.T) {
	tc := setupWitnessTestContext(t)

	appendEntry(t, tc.log, "A")

	cp, err := tc.log.Checkpoint()
	if err != nil {
		t.Fatal(err)
	}

	result, err := tc.witness.ObserveCheckpoint(cp, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.WitnessSignature == nil {
		t.Fatal("expected witness signature")
	}

	if tc.witness.lastCheckpoint == nil {
		t.Fatal("witness did not store checkpoint")
	}
}

// TEST 2 — crescita consistente
func TestWitness_ConsistentGrowth(t *testing.T) {
	tc := setupWitnessTestContext(t)

	appendEntry(t, tc.log, "A")
	cp1, _ := tc.log.Checkpoint()

	_, err := tc.witness.ObserveCheckpoint(cp1, nil)
	if err != nil {
		t.Fatal(err)
	}

	appendEntry(t, tc.log, "B")
	appendEntry(t, tc.log, "C")
	cp3, _ := tc.log.Checkpoint()

	proof, err := tc.log.ConsistencyProof(1, 3)
	if err != nil {
		t.Fatal(err)
	}

	result, err := tc.witness.ObserveCheckpoint(cp3, proof)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.WitnessSignature == nil {
		t.Fatal("expected witness signature")
	}

	if tc.witness.lastCheckpoint.TreeSize != 3 {
		t.Fatal("witness did not update checkpoint")
	}
}

// TEST 3 — firma log falsa
func TestWitness_InvalidLogSignature(t *testing.T) {
	tc := setupWitnessTestContext(t)

	appendEntry(t, tc.log, "A")
	cp, _ := tc.log.Checkpoint()

	fake := cp
	fake.Signature = make([]byte, len(cp.Signature))
	copy(fake.Signature, cp.Signature)
	fake.Signature[0] ^= 0xFF

	_, err := tc.witness.ObserveCheckpoint(fake, nil)
	if err == nil {
		t.Fatal("expected error for invalid log signature")
	}
}

// TEST 4 — tree più piccolo
func TestWitness_SmallerTree(t *testing.T) {
	tc := setupWitnessTestContext(t)

	appendEntry(t, tc.log, "A")
	appendEntry(t, tc.log, "B")
	appendEntry(t, tc.log, "C")

	cp3, _ := tc.log.Checkpoint()

	_, err := tc.witness.ObserveCheckpoint(cp3, nil)
	if err != nil {
		t.Fatal(err)
	}

	// costruiamo un checkpoint più piccolo con un altro log
	tc2 := setupWitnessTestContext(t)
	appendEntry(t, tc2.log, "A")
	appendEntry(t, tc2.log, "B")

	cp2, _ := tc2.log.Checkpoint()

	_, err = tc.witness.ObserveCheckpoint(cp2, nil)
	if err == nil {
		t.Fatal("expected error for smaller tree")
	}
}

// TEST 5 — stessa size, root diversa
func TestWitness_SameSizeDifferentRoot(t *testing.T) {
	tc := setupWitnessTestContext(t)

	appendEntry(t, tc.log, "A")
	cp1, _ := tc.log.Checkpoint()

	_, _ = tc.witness.ObserveCheckpoint(cp1, nil)

	fake := cp1
	fake.RootHash = make([]byte, len(cp1.RootHash))
	copy(fake.RootHash, cp1.RootHash)
	fake.RootHash[0] ^= 0xFF

	_, err := tc.witness.ObserveCheckpoint(fake, nil)
	if err == nil {
		t.Fatal("expected error for same size different root")
	}
}

func TestWitness_InvalidConsistencyProof(t *testing.T) {
	tc := setupWitnessTestContext(t)

	appendEntry(t, tc.log, "A")
	cp1, _ := tc.log.Checkpoint()

	_, _ = tc.witness.ObserveCheckpoint(cp1, nil)

	appendEntry(t, tc.log, "B")
	appendEntry(t, tc.log, "C")
	cp3, _ := tc.log.Checkpoint()

	proof, _ := tc.log.ConsistencyProof(1, 3)

	badProof := cloneProof(proof)
	badProof[0][0] ^= 0xFF

	_, err := tc.witness.ObserveCheckpoint(cp3, badProof)
	if err == nil {
		t.Fatal("expected error for invalid consistency proof")
	}
}

// Per runnare il test: go test ./bb -run Witness -v
