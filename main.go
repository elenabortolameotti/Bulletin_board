/*package main

import (
	"bb-project/bb"
	"bb-project/bb/model"
	chash "bb-project/c ryptography/hash"
	"bb-project/cryptography/signature"
	"fmt"
)

//Per sunlight
//func main() {
//	fmt.Println("TileHeight:", sunlight.TileHeight)
//	fmt.Println("TileWidth:", sunlight.TileWidth)
//}

// authenticity
func VerifyCheckpoint(
	scheme signature.Scheme,
	publicKey []byte,
	cp bb.Checkpoint,
) (bool, error) {

	data, err := cp.EncodeForSigning()
	if err != nil {
		return false, err
	}
	ok := scheme.Verify(publicKey, data, cp.Signature)
	return ok, nil
}

func main() {

	// 1. base hash
	baseHash := chash.SHA256Scheme{}

	// 2. merkle hasher
	merkleHasher := chash.MerkleTreeHash{
		BaseHash: baseHash,
	}

	// 3. signer
	// QUESTA PARTE VA ADATTATA al tuo codice concreto in signature/
	// Se hai già chiavi hardcodate o una funzione di generazione, usa quella.

	publicKey, privateKey, err := signature.GenerateEd25519KeyPair()
	if err != nil {
		panic(err)
	}

	signer := signature.NewEd25519Signer(publicKey, privateKey)

	// 4. log
	log := bb.NewLog(merkleHasher, signer)

	// 5. entry
	entry := model.Entry{
		EntryType:   "ballot",
		Context:     "test-election",
		Payload:     []byte("vote:Alice"),
		SubmitterID: []byte("voter-001"),
		Timestamp:   "2026-03-31T10:00:00Z",
	}

	// 6. append
	receipt, err := log.Append(entry)
	if err != nil {
		panic(err)
	}

	ok, err := VerifyCheckpoint(
		signature.Ed25519Scheme{},
		signer.PublicKey(),
		receipt.Checkpoint,
	)
	if err != nil {
		panic(err)
	}

	// 7. stampa receipt
	fmt.Println("----- RECEIPT -----")
	fmt.Println("EntryID:", receipt.EntryID)
	fmt.Println("Index:", receipt.Index)
	fmt.Printf("LeafHash: %x\n", receipt.LeafHash)

	fmt.Println("----- CHECKPOINT -----")
	fmt.Println("TreeSize:", receipt.Checkpoint.TreeSize)
	fmt.Printf("RootHash: %x\n", receipt.Checkpoint.RootHash)
	fmt.Printf("Signature: %x\n", receipt.Checkpoint.Signature)

	// 8. verifica il checkpoint
	fmt.Println("\n---- VERIFY CHECKPOINT ----")
	fmt.Println("Valid signature:", ok)

}*/

package main

import (
	"fmt"

	"bb-project/bb"
	"bb-project/bb/model"
	chash "bb-project/cryptography/hash"
	"bb-project/cryptography/signature"
)

func main() {
	// =========================
	// 1. Setup
	// =========================
	baseHash := chash.SHA256Scheme{}
	merkleHasher := chash.MerkleTreeHash{
		BaseHash: baseHash,
	}

	publicKey, privateKey, err := signature.GenerateEd25519KeyPair()
	if err != nil {
		panic(err)
	}

	signer := signature.NewEd25519Signer(publicKey, privateKey)
	scheme := signature.Ed25519Scheme{}

	log := bb.NewLog(merkleHasher, signer)
	verifier := bb.NewVerifier(scheme, publicKey, merkleHasher)

	// =========================
	// 2. Creazione entry
	// =========================
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

	// =========================
	// 3. Append 1
	// =========================
	receipt1, err := log.Append(entry1)
	if err != nil {
		panic(err)
	}

	cp1, err := log.Checkpoint()
	if err != nil {
		panic(err)
	}

	proof1cp1, err := log.InclusionProof(receipt1.Index)
	if err != nil {
		panic(err)
	}

	fmt.Println("===== CHECKPOINT 1 =====")
	fmt.Println("TreeSize:", cp1.TreeSize)
	fmt.Printf("RootHash: %x\n", cp1.RootHash)
	fmt.Printf("Signature: %x\n", cp1.Signature)
	fmt.Println()

	// =========================
	// 4. Append 2
	// =========================
	receipt2, err := log.Append(entry2)
	if err != nil {
		panic(err)
	}

	cp2, err := log.Checkpoint()
	if err != nil {
		panic(err)
	}

	fmt.Println("===== CHECKPOINT 2 =====")
	fmt.Println("TreeSize:", cp2.TreeSize)
	fmt.Printf("RootHash: %x\n", cp2.RootHash)
	fmt.Printf("Signature: %x\n", cp2.Signature)
	fmt.Println()

	// =========================
	// 5. Append 3
	// =========================
	receipt3, err := log.Append(entry3)
	if err != nil {
		panic(err)
	}

	cp3, err := log.Checkpoint()
	if err != nil {
		panic(err)
	}

	fmt.Println("===== CHECKPOINT 3 =====")
	fmt.Println("TreeSize:", cp3.TreeSize)
	fmt.Printf("RootHash: %x\n", cp3.RootHash)
	fmt.Printf("Signature: %x\n", cp3.Signature)
	fmt.Println()

	// =========================
	// 6. Proof nello stato finale (checkpoint 3)
	// =========================
	proof1cp3, err := log.InclusionProof(receipt1.Index)
	if err != nil {
		panic(err)
	}

	proof2cp3, err := log.InclusionProof(receipt2.Index)
	if err != nil {
		panic(err)
	}

	proof3cp3, err := log.InclusionProof(receipt3.Index)
	if err != nil {
		panic(err)
	}

	// receipt coerenti coi checkpoint che vogliamo verificare
	receipt1cp1 := receipt1
	receipt1cp1.Checkpoint = cp1

	receipt1cp3 := receipt1
	receipt1cp3.Checkpoint = cp3

	receipt2cp3 := receipt2
	receipt2cp3.Checkpoint = cp3

	receipt3cp3 := receipt3
	receipt3cp3.Checkpoint = cp3

	// =========================
	// 7. Verifiche
	// =========================

	// Entry 1 nel checkpoint 1
	ok, err := verifier.VerifyEntryInCheckpoint(
		entry1,
		receipt1cp1,
		proof1cp1,
	)
	if err != nil {
		panic(err)
	}
	fmt.Println("Verify entry1 in checkpoint1:", ok)

	// Entry 1 nel checkpoint 3
	ok, err = verifier.VerifyEntryInCheckpoint(
		entry1,
		receipt1cp3,
		proof1cp3,
	)
	if err != nil {
		panic(err)
	}
	fmt.Println("Verify entry1 in checkpoint3:", ok)

	// Entry 2 nel checkpoint 3
	ok, err = verifier.VerifyEntryInCheckpoint(
		entry2,
		receipt2cp3,
		proof2cp3,
	)
	if err != nil {
		panic(err)
	}
	fmt.Println("Verify entry2 in checkpoint3:", ok)

	// Entry 3 nel checkpoint 3
	ok, err = verifier.VerifyEntryInCheckpoint(
		entry3,
		receipt3cp3,
		proof3cp3,
	)
	if err != nil {
		panic(err)
	}
	fmt.Println("Verify entry3 in checkpoint3:", ok)

	fmt.Println()

	// =========================
	// 8. Caso negativo di esempio
	// =========================
	modifiedEntry1 := entry1
	modifiedEntry1.Payload = []byte("vote:Mallory")

	ok, err = verifier.VerifyEntryInCheckpoint(
		modifiedEntry1,
		receipt1cp3,
		proof1cp3,
	)
	if err != nil {
		panic(err)
	}
	fmt.Println("Verify modified entry1 in checkpoint3:", ok)
}
