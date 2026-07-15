package logging

import (
	"testing"

	"github.com/go-ctap/kit/model"
)

func TestJournalReadsFromCursor(t *testing.T) {
	journal := NewJournal(3, 1<<20)
	journal.Append(model.LogEntry{Code: "first"})
	cursor := journal.Cursor()
	journal.Append(model.LogEntry{Code: "second"})

	batch := journal.Read(cursor)
	if batch.Cursor != 2 || batch.Truncated || len(batch.Entries) != 1 || batch.Entries[0].Entry.Code != "second" {
		t.Fatalf("batch = %#v", batch)
	}
}

func TestJournalReportsRetentionGap(t *testing.T) {
	journal := NewJournal(2, 1<<20)
	journal.Append(model.LogEntry{Code: "first"})
	journal.Append(model.LogEntry{Code: "second"})
	journal.Append(model.LogEntry{Code: "third"})

	batch := journal.Read(0)
	if !batch.Truncated || len(batch.Entries) != 2 || batch.Entries[0].Sequence != 2 {
		t.Fatalf("batch = %#v", batch)
	}
}

func TestJournalClearKeepsCursorMonotonic(t *testing.T) {
	journal := NewJournal(3, 1<<20)
	journal.Append(model.LogEntry{Code: "before"})
	cursor := journal.Clear()
	journal.Append(model.LogEntry{Code: "after"})

	batch := journal.Read(cursor)
	if batch.Cursor != 2 || batch.Truncated || len(batch.Entries) != 1 || batch.Entries[0].Entry.Code != "after" {
		t.Fatalf("batch = %#v", batch)
	}
}

func TestJournalClearDoesNotReportRetentionGapToFreshReader(t *testing.T) {
	journal := NewJournal(3, 1<<20)
	journal.Append(model.LogEntry{Code: "before"})
	journal.Clear()
	journal.Append(model.LogEntry{Code: "after"})

	batch := journal.Read(0)
	if batch.Cursor != 2 || batch.Truncated || len(batch.Entries) != 1 || batch.Entries[0].Entry.Code != "after" {
		t.Fatalf("batch = %#v", batch)
	}
}

func TestJournalCoalescesChangeNotifications(t *testing.T) {
	journal := NewJournal(3, 1<<20)
	journal.Append(model.LogEntry{Code: "first"})
	journal.Append(model.LogEntry{Code: "second"})

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
