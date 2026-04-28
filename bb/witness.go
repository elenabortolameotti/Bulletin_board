package bb

import (
	"bb-project/cryptography/hash"
	"bb-project/cryptography/signature"
	"bytes"
	"errors"
)

type Witness struct {
	signer         signature.Signer
	verifier       *Verifier
	lastCheckpoint *Checkpoint
}

type WitnessedCheckpoint struct {
	Checkpoint       Checkpoint
	WitnessSignature []byte
}

type WitnessVerifier struct {
	logVerifier      *Verifier
	witnessScheme    signature.Scheme
	witnessPublicKey []byte
}

func NewWitness(
	signer signature.Signer,
	logScheme signature.Scheme,
	logPublicKey []byte,
	hasher hash.MerkleTreeHash,
) *Witness {
	return &Witness{
		signer:   signer,
		verifier: NewVerifier(logScheme, logPublicKey, hasher),
	}
}

func NewWitnessVerifier(
	logScheme signature.Scheme,
	logPublicKey []byte,
	hasher hash.MerkleTreeHash,
	witnessScheme signature.Scheme,
	witnessPublicKey []byte,
) *WitnessVerifier {
	wpkCopy := make([]byte, len(witnessPublicKey))
	copy(wpkCopy, witnessPublicKey)

	return &WitnessVerifier{
		logVerifier:      NewVerifier(logScheme, logPublicKey, hasher),
		witnessScheme:    witnessScheme,
		witnessPublicKey: wpkCopy,
	}
}

func (w *Witness) ObserveCheckpoint(
	cp Checkpoint,
	proof [][]byte,
) (WitnessedCheckpoint, error) {
	ok, err := w.verifier.VerifyCheckpoint(cp)
	if err != nil {
		return WitnessedCheckpoint{}, err
	}
	if !ok {
		return WitnessedCheckpoint{}, errors.New("invalid log signature on checkpoint")
	}

	data, err := cp.EncodeForSigning()
	if err != nil {
		return WitnessedCheckpoint{}, err
	}

	if w.lastCheckpoint == nil {
		checkpointCopy := cp
		w.lastCheckpoint = &checkpointCopy

		witnessSig, err := w.signer.Sign(data)
		if err != nil {
			return WitnessedCheckpoint{}, err
		}

		return WitnessedCheckpoint{
			Checkpoint:       cp,
			WitnessSignature: witnessSig,
		}, nil
	}

	old := w.lastCheckpoint

	if cp.TreeSize < old.TreeSize {
		return WitnessedCheckpoint{}, errors.New("the size of the new tree is smaller than the old one")
	}

	if cp.TreeSize == old.TreeSize {
		if !bytes.Equal(cp.RootHash, old.RootHash) {
			return WitnessedCheckpoint{}, errors.New("same tree size but different root hash")
		}

		witnessSig, err := w.signer.Sign(data)
		if err != nil {
			return WitnessedCheckpoint{}, err
		}

		return WitnessedCheckpoint{
			Checkpoint:       cp,
			WitnessSignature: witnessSig,
		}, nil
	}

	ok = w.verifier.VerifyConsistencyProof(*old, cp, proof)
	if !ok {
		return WitnessedCheckpoint{}, errors.New("verification of consistency proof failed")
	}

	checkpointCopy := cp
	w.lastCheckpoint = &checkpointCopy

	witnessSig, err := w.signer.Sign(data)
	if err != nil {
		return WitnessedCheckpoint{}, err
	}

	return WitnessedCheckpoint{
		Checkpoint:       cp,
		WitnessSignature: witnessSig,
	}, nil
}

func (wv *WitnessVerifier) VerifyWitnessedCheckpoint(
	wcp WitnessedCheckpoint,
) (bool, error) {
	cp := wcp.Checkpoint

	ok, err := wv.logVerifier.VerifyCheckpoint(cp)
	if err != nil {
		return false, err
	}
	if !ok {
		return false, nil
	}

	data, err := cp.EncodeForSigning()
	if err != nil {
		return false, err
	}

	ok = wv.witnessScheme.Verify(wv.witnessPublicKey, data, wcp.WitnessSignature)
	if !ok {
		return false, nil
	}

	return true, nil
}
