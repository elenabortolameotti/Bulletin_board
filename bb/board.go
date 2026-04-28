package bb

import (
	"bb-project/bb/model"
	"errors"
)

type BulletinBoard struct {
	entries []model.Entry
}

// creation of a new empty BB
func New() *BulletinBoard {
	return &BulletinBoard{
		entries: []model.Entry{},
	}
}

// publish a generic entry
func (b *BulletinBoard) Publish(entry model.Entry) Receipt {
	b.entries = append(b.entries, entry)

	return Receipt{
		Index: len(b.entries) - 1,
	}
}

// search for an entry by ID
func (b *BulletinBoard) GetByID(entryID string) (model.Entry, error) {
	for _, entry := range b.entries {
		if entry.EntryID == entryID {
			return entry, nil
		}
	}
	return model.Entry{}, errors.New("entry not found")
}

// return all entries
func (b *BulletinBoard) All() []model.Entry {
	return b.entries
}
