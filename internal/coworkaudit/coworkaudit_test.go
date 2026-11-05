// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package coworkaudit

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
)

// The lookup reads the rows the audit store writes: claudecode hook rows
// whose envelope carries "surface":"cowork", grouped by the OS-derived
// caller identity, the newest per account.
func TestLastEventsReadsCoworkRowsPerAccount(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.db")
	store, err := audit.NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	base := time.Date(2026, 11, 3, 13, 0, 0, 0, time.UTC)
	for _, row := range []struct {
		connector, surface, uid, name string
		at                            time.Time
	}{
		{"claudecode", "cowork", "501", "alice", base},
		{"claudecode", "cowork", "501", "alice", base.Add(2 * time.Minute)},
		{"claudecode", "cowork", "502", "bob", base.Add(time.Minute)},
		{"claudecode", "extra", "502", "bob", base.Add(90 * time.Second)},
		{"claudecode", "", "503", "carol", base.Add(3 * time.Minute)}, // Claude Code CLI
		{"codex", "cowork", "504", "dave", base.Add(4 * time.Minute)}, // another connector
	} {
		structured := map[string]any{"user.id": row.uid, "defenseclaw.user.name": row.name, "event": "PreToolUse"}
		switch row.surface {
		case "":
		case "extra":
			structured["extra"] = map[string]any{"surface": "cowork"}
		default:
			structured["surface"] = row.surface
		}
		if err := store.LogEvent(audit.Event{Action: "connector-hook", Connector: row.connector, Timestamp: row.at, Structured: structured}); err != nil {
			t.Fatal(err)
		}
	}
	got, truncated, err := LastEvents(context.Background(), path)
	if err != nil || truncated {
		t.Fatal(err, truncated)
	}
	want := map[string]time.Time{"alice": base.Add(2 * time.Minute), "bob": base.Add(90 * time.Second)}
	if len(got) != len(want) {
		t.Fatalf("LastEvents = %+v, want %v", got, want)
	}
	for _, event := range got {
		if at, ok := want[event.UserName]; !ok || !at.Equal(event.At) || event.UserID == "" {
			t.Fatalf("LastEvents = %+v, want %v", got, want)
		}
	}
	old := maxAccounts
	maxAccounts = 1
	t.Cleanup(func() { maxAccounts = old })
	if got, truncated, err := LastEvents(context.Background(), path); err != nil || !truncated || len(got) != 1 || got[0].UserName != "alice" {
		t.Fatalf("at the row bound: %+v truncated=%v err=%v", got, truncated, err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
}

// A WAL store nobody has open is not opened: a read-only open would create
// its shared-memory file as the caller.
func TestLastEventsNeverCreatesTheSharedMemoryFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.db")
	for _, name := range []string{path, path + "-wal"} {
		if err := os.WriteFile(name, nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := LastEvents(context.Background(), path); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("LastEvents = %v, want ErrUnavailable", err)
	}
	if _, err := os.Lstat(path + "-shm"); err == nil {
		t.Fatal("the lookup created the shared-memory file")
	}
	if _, _, err := LastEvents(context.Background(), "audit.db"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("relative path: %v", err)
	}
	if _, _, err := LastEvents(context.Background(), filepath.Join(dir, "missing.db")); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("missing store: %v", err)
	}
}
