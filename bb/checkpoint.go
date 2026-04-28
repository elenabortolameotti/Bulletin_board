package bb

import "encoding/json"

type Checkpoint struct {
	TreeSize  int
	RootHash  []byte
	Signature []byte
}

func (l *Log) Checkpoint() (Checkpoint, error) {
	cp := Checkpoint{
		TreeSize: l.Size(),
		RootHash: l.Root(),
	}

	data, err := cp.EncodeForSigning()
	if err != nil {
		return Checkpoint{}, err
	}

	sig, err := l.signer.Sign(data)
	if err != nil {
		return Checkpoint{}, err
	}

	cp.Signature = sig

	return cp, nil
}

type checkpointForSigning struct {
	TreeSize int
	RootHash []byte
}

func (c *Checkpoint) EncodeForSigning() ([]byte, error) {
	tmp := checkpointForSigning{
		TreeSize: c.TreeSize,
		RootHash: c.RootHash,
	}

	return json.Marshal(tmp)
}
