package logging

import (
	"testing"

	"github.com/go-ctap/kit/model"
)

func TestJournalReadsFromCursor(t *testing.T) {
	journal := NewJournal(3, 1<<20)
	journal.Append(model.LogEntry{Command: "first"})
	cursor := journal.Cursor()
	journal.Append(model.LogEntry{Command: "second"})

	batch := journal.Read(cursor)
	if batch.Cursor != 2 || batch.Truncated || len(batch.Entries) != 1 || batch.Entries[0].Entry.Command != "second" {
		t.Fatalf("batch = %#v", batch)
	}
}

func TestJournalReportsRetentionGap(t *testing.T) {
	journal := NewJournal(2, 1<<20)
	journal.Append(model.LogEntry{Command: "first"})
	journal.Append(model.LogEntry{Command: "second"})
	journal.Append(model.LogEntry{Command: "third"})

	batch := journal.Read(0)
	if !batch.Truncated || len(batch.Entries) != 2 || batch.Entries[0].Sequence != 2 {
		t.Fatalf("batch = %#v", batch)
	}
}

func TestJournalClearKeepsCursorMonotonic(t *testing.T) {
	journal := NewJournal(3, 1<<20)
	journal.Append(model.LogEntry{Command: "before"})
	cursor := journal.Clear()
	journal.Append(model.LogEntry{Command: "after"})

	batch := journal.Read(cursor)
	if batch.Cursor != 2 || batch.Truncated || len(batch.Entries) != 1 || batch.Entries[0].Entry.Command != "after" {
		t.Fatalf("batch = %#v", batch)
	}
}

func TestJournalClearDoesNotReportRetentionGapToFreshReader(t *testing.T) {
	journal := NewJournal(3, 1<<20)
	journal.Append(model.LogEntry{Command: "before"})
	journal.Clear()
	journal.Append(model.LogEntry{Command: "after"})

	batch := journal.Read(0)
	if batch.Cursor != 2 || batch.Truncated || len(batch.Entries) != 1 || batch.Entries[0].Entry.Command != "after" {
		t.Fatalf("batch = %#v", batch)
	}
}

func TestJournalCoalescesChangeNotifications(t *testing.T) {
	journal := NewJournal(3, 1<<20)
	journal.Append(model.LogEntry{Command: "first"})
	journal.Append(model.LogEntry{Command: "second"})

	select {
	case <-journal.Changes():
	default:
		t.Fatal("change notification is missing")
	}

	select {
	case <-journal.Changes():
		t.Fatal("change notifications were not coalesced")
	default:
	}
}
