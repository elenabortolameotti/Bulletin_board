package model

import (
	"encoding/json"
)

type Entry struct {
	EntryID   string `json:"entry_ID"`
	EntryType string `json:"entry_type"`
	Context   string `json:"context"`
	Payload   []byte `json:"payload"`

	SubmitterID []byte `json:"submitter_id,omitempty"`
	Signature   []byte `json:"signature,omitempty"`

	Timestamp string `json:"timestamp,omitempty"`
}

type EntryForSigning struct {
	EntryID     string `json:"entry_ID"`
	EntryType   string `json:"entry_type"`
	Context     string `json:"context"`
	Payload     []byte `json:"payload"`
	SubmitterID []byte `json:"submitter_id,omitempty"`
	Timestamp   string `json:"timestamp,omitempty"`
}

func (e *Entry) EncodeForSigning() ([]byte, error) {
	tmp := EntryForSigning{
		EntryID:     e.EntryID,
		EntryType:   e.EntryType,
		Context:     e.Context,
		Payload:     e.Payload,
		SubmitterID: e.SubmitterID,
		Timestamp:   e.Timestamp,
	}

	data, err := json.Marshal(tmp)
	if err != nil {
		return nil, err
	}

	return data, nil
}

// 1) costruisco entry
// 2) costruisco entry senza firma
// 3) creo la versione firmabile: msg := e.EncodeForSigning()
// 4) firma: sig := Sign(sk, msg)
// 5) aggiung firma: e.Signature = sig
