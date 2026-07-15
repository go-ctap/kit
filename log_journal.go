package ctapkit

import (
	"github.com/go-ctap/kit/internal/logging"
	"github.com/go-ctap/kit/model"
)

const (
	logJournalEntryLimit = 2_000
	logJournalByteLimit  = 16 * 1024 * 1024
)

// LogJournal is a bounded, in-memory record of runtime activity.
type LogJournal struct {
	journal *logging.Journal
}

func NewLogJournal() *LogJournal {
	return &LogJournal{journal: logging.NewJournal(logJournalEntryLimit, logJournalByteLimit)}
}

func (j *LogJournal) Append(entry model.LogEntry) {
	j.journal.Append(entry)
}

func (j *LogJournal) Read(after uint64) model.LogJournalBatch {
	return j.journal.Read(after)
}

func (j *LogJournal) Clear() uint64 {
	return j.journal.Clear()
}

func (j *LogJournal) Cursor() uint64 {
	return j.journal.Cursor()
}

func (j *LogJournal) Changes() <-chan struct{} {
	return j.journal.Changes()
}
