package bb

import (
	"testing"

	"bb-project/bb/model"
	chash "bb-project/cryptography/hash"
	"bb-project/cryptography/signature"
)

type witnessedCheckpointTestContext struct {
	log              *Log
	witness          *Witness
	witnessVerifier  *WitnessVerifier
	hasher           chash.MerkleTreeHash
	logScheme        signature.Scheme
	logPublicKey     []byte
	witnessScheme    signature.Scheme
	witnessPublicKey []byte
}

func setupWitnessedCheckpointTestContext(t *testing.T) witnessedCheckpointTestContext {
	t.Helper()

	baseHash := chash.SHA256Scheme{}
	hasher := chash.MerkleTreeHash{
		BaseHash: baseHash,
	}

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

	logScheme := signature.Ed25519Scheme{}
	witnessScheme := signature.Ed25519Scheme{}

	log := NewLog(hasher, logSigner)

	w := NewWitness(
		wSigner,
		logScheme,
		logPub,
		hasher,
	)

	wv := NewWitnessVerifier(
		logScheme,
		logPub,
		hasher,
		witnessScheme,
		wPub,
	)

	return witnessedCheckpointTestContext{
		log:              log,
		witness:          w,
		witnessVerifier:  wv,
		hasher:           hasher,
		logScheme:        logScheme,
		logPublicKey:     logPub,
		witnessScheme:    witnessScheme,
		witnessPublicKey: wPub,
	}
}

func appendWitnessedEntry(t *testing.T, log *Log, payload string) {
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

func cloneBytesWC(b []byte) []byte {
	if b == nil {
		return nil
	}
	out := make([]byte, len(b))
	copy(out, b)
	return out
}

func TestVerifyWitnessedCheckpoint_Valid(t *testing.T) {
	tc := setupWitnessedCheckpointTestContext(t)

	appendWitnessedEntry(t, tc.log, "A")

	cp, err := tc.log.Checkpoint()
	if err != nil {
		t.Fatal(err)
	}

	wcp, err := tc.witness.ObserveCheckpoint(cp, nil)
	if err != nil {
		t.Fatalf("unexpected error from witness: %v", err)
	}

	ok, err := tc.witnessVerifier.VerifyWitnessedCheckpoint(wcp)
	if err != nil {
		t.Fatalf("unexpected error during verification: %v", err)
	}
	if !ok {
		t.Fatal("expected witnessed checkpoint to be valid")
	}
}

func TestVerifyWitnessedCheckpoint_ModifiedWitnessSignature(t *testing.T) {
	tc := setupWitnessedCheckpointTestContext(t)

	appendWitnessedEntry(t, tc.log, "A")

	cp, err := tc.log.Checkpoint()
	if err != nil {
		t.Fatal(err)
	}

	wcp, err := tc.witness.ObserveCheckpoint(cp, nil)
	if err != nil {
		t.Fatalf("unexpected error from witness: %v", err)
	}

	bad := wcp
	bad.WitnessSignature = cloneBytesWC(wcp.WitnessSignature)
	bad.WitnessSignature[0] ^= 0xFF

	ok, err := tc.witnessVerifier.VerifyWitnessedCheckpoint(bad)
	if err != nil {
		t.Fatalf("unexpected error during verification: %v", err)
	}
	if ok {
		t.Fatal("expected verification to fail for modified witness signature")
	}
}

func TestVerifyWitnessedCheckpoint_ModifiedLogSignature(t *testing.T) {
	tc := setupWitnessedCheckpointTestContext(t)

	appendWitnessedEntry(t, tc.log, "A")

	cp, err := tc.log.Checkpoint()
	if err != nil {
		t.Fatal(err)
	}

	wcp, err := tc.witness.ObserveCheckpoint(cp, nil)
	if err != nil {
		t.Fatalf("unexpected error from witness: %v", err)
	}

	bad := wcp
	bad.Checkpoint.Signature = cloneBytesWC(wcp.Checkpoint.Signature)
	bad.Checkpoint.Signature[0] ^= 0xFF

	ok, err := tc.witnessVerifier.VerifyWitnessedCheckpoint(bad)
	if err != nil {
		t.Fatalf("unexpected error during verification: %v", err)
	}
	if ok {
		t.Fatal("expected verification to fail for modified log signature")
	}
}

func TestVerifyWitnessedCheckpoint_WrongWitnessPublicKey(t *testing.T) {
	tc := setupWitnessedCheckpointTestContext(t)

	appendWitnessedEntry(t, tc.log, "A")

	cp, err := tc.log.Checkpoint()
	if err != nil {
		t.Fatal(err)
	}

	wcp, err := tc.witness.ObserveCheckpoint(cp, nil)
	if err != nil {
		t.Fatalf("unexpected error from witness: %v", err)
	}

	wrongWitnessPub, _, err := signature.GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("failed to generate wrong witness key: %v", err)
	}

	wrongWV := NewWitnessVerifier(
		tc.logScheme,
		tc.logPublicKey,
		tc.hasher,
		tc.witnessScheme,
		wrongWitnessPub,
	)

	ok, err := wrongWV.VerifyWitnessedCheckpoint(wcp)
	if err != nil {
		t.Fatalf("unexpected error during verification: %v", err)
	}
	if ok {
		t.Fatal("expected verification to fail with wrong witness public key")
	}
}

func TestVerifyWitnessedCheckpoint_WrongLogPublicKey(t *testing.T) {
	tc := setupWitnessedCheckpointTestContext(t)

	appendWitnessedEntry(t, tc.log, "A")

	cp, err := tc.log.Checkpoint()
	if err != nil {
		t.Fatal(err)
	}

	wcp, err := tc.witness.ObserveCheckpoint(cp, nil)
	if err != nil {
		t.Fatalf("unexpected error from witness: %v", err)
	}

	wrongLogPub, _, err := signature.GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("failed to generate wrong log key: %v", err)
	}

	wrongWV := NewWitnessVerifier(
		tc.logScheme,
		wrongLogPub,
		tc.hasher,
		tc.witnessScheme,
		tc.witnessPublicKey,
	)

	ok, err := wrongWV.VerifyWitnessedCheckpoint(wcp)
	if err != nil {
		t.Fatalf("unexpected error during verification: %v", err)
	}
	if ok {
		t.Fatal("expected verification to fail with wrong log public key")
	}
}

// Per testare: go test ./bb -run WitnessedCheckpoint -v
