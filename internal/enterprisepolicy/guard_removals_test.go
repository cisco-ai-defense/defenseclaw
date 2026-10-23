// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"errors"
	"strconv"
	"testing"
	"time"
)

// Review P2 (GAP-0352, loop round 4): one account's many removals must not
// evict another account's only one. Before, a ledger over 1024 entries
// kept the newest of all accounts, so a user's 1024 newer removals dropped
// another account's removal while that account's agent still ran the
// removed hook, and the agent was allowed again. Each account and
// connector keeps its horizon, the entry that denies every process any of
// its entries denies, for as long as its newest entry lives; only accounts
// whose horizons alone overflow the ledger are dropped, and they are
// returned for the guardian to hold.
func TestForeignHookRemovalLedgerKeepsEveryAccountsDenialWhenFull(t *testing.T) {
	now := time.Now()
	at := func(age time.Duration) string { return now.Add(-age).UTC().Format(time.RFC3339) }
	victim := []ForeignHookRemoval{{Identity: "1002", Connector: "copilot", Path: "/home/v/.copilot/hooks/a.json", At: at(3 * time.Hour), Mark: "linux:b:500"}}
	var flood []ForeignHookRemoval
	for i := 0; i < 3000; i++ {
		flood = append(flood, ForeignHookRemoval{Identity: "1001", Connector: []string{"copilot", "codex", "claudecode"}[i%3],
			Path: "/home/a/" + strconv.Itoa(i), At: at(time.Hour), Mark: "linux:b:900"})
	}
	// An earlier wall-clock time with a later mark (the clock was set
	// back): the horizon keeps the latest mark and the newest time.
	flood = append(flood, ForeignHookRemoval{Identity: "1001", Connector: "copilot", Path: "/home/a/late", At: at(5 * time.Hour), Mark: "linux:b:999"})
	data, err := EncodeForeignHookRemovals(victim, flood, now)
	if err != nil {
		t.Fatal(err)
	}
	removals, err := ParseForeignHookRemovals(data)
	if err != nil {
		t.Fatal(err)
	}
	of := func(identity string) []ForeignHookRemoval {
		var out []ForeignHookRemoval
		for _, removal := range removals {
			if removal.Identity == identity {
				out = append(out, removal)
			}
		}
		return out
	}
	denied := func(identity, connector, process string, when time.Time) bool {
		key := SessionKey{Connector: connector, Session: "s", Process: process}
		return ApplyForeignHookRemovals(GuardDecision{}, key, of(identity), nil, when).Deny
	}
	if !denied("1002", "copilot", "linux:b:42:100", now) {
		t.Fatal("another account's removal must survive the flood")
	}
	if denied("1002", "copilot", "linux:b:43:600", now) {
		t.Fatal("an agent of that account started after its removal stays allowed")
	}
	for _, name := range []string{"copilot", "codex", "claudecode"} {
		if !denied("1001", name, "linux:b:44:800", now) {
			t.Fatalf("the flooding account keeps its own %s denial", name)
		}
	}
	if !denied("1001", "copilot", "linux:b:45:950", now) {
		t.Fatal("the horizon keeps the latest mark of the pair")
	}
	if !denied("1001", "copilot", "linux:b:46:950", now.Add(sessionRecordTTL-90*time.Minute)) {
		t.Fatal("the horizon lives as long as the pair's newest entry")
	}

	// More pairs than the ledger holds: the encoding fails, so the guardian
	// removes nothing (the hook stays and the scan keeps blocking) rather
	// than drop an account's denial.
	var many []ForeignHookRemoval
	for i := 0; i < foreignHookRemovalsLimit+10; i++ {
		many = append(many, ForeignHookRemoval{Identity: strconv.Itoa(5000 + i), Connector: "copilot", Path: "/x",
			At: now.Add(-time.Duration(i) * time.Minute).UTC().Format(time.RFC3339), Mark: "linux:b:900"})
	}
	if _, err = EncodeForeignHookRemovals(nil, many, now); !errors.Is(err, ErrForeignHookRemovalLedgerFull) {
		t.Fatalf("a ledger that cannot keep every account's denial must not be written: %v", err)
	}
	if _, err = EncodeForeignHookRemovals(nil, many[:foreignHookRemovalsLimit], now); err != nil {
		t.Fatalf("a ledger that holds every pair is written: %v", err)
	}
}

// W4 re-fix loop 3: per account, connector and file the removal with the
// later mark wins, whatever order the guardian processes published in, so
// an older cleanup published last never erases a newer removal; a commit
// drops only its own first record (matched without its time, which the
// horizon may move).
func TestForeignHookRemovalLaterMarkWinsAndTheCommitDropsItsFirstRecord(t *testing.T) {
	now := time.Now().UTC()
	at := func(d time.Duration) string { return now.Add(d).Format(time.RFC3339Nano) }
	newer := ForeignHookRemoval{Identity: "1001", Connector: "cursor", Path: "/h/.cursor/hooks.json", At: at(-time.Minute), Mark: "linux:b:900"}
	older := ForeignHookRemoval{Identity: "1001", Connector: "cursor", Path: "/h/.cursor/hooks.json", At: at(0), Mark: "linux:b:500"}
	data, err := EncodeForeignHookRemovals([]ForeignHookRemoval{newer}, []ForeignHookRemoval{older}, now)
	if err != nil {
		t.Fatal(err)
	}
	removals, err := ParseForeignHookRemovals(data)
	if err != nil || len(removals) != 1 || removals[0].Mark != newer.Mark {
		t.Fatalf("the later mark must win over an older cleanup published last: %+v %v", removals, err)
	}
	key := SessionKey{Connector: "cursor", Session: "s", Process: "linux:b:1:700"}
	if !ApplyForeignHookRemovals(GuardDecision{}, key, removals, nil, now).Deny {
		t.Fatal("an agent that started before the newer removal must stay denied")
	}
	first := ForeignHookRemoval{Identity: "1001", Connector: "cursor", Path: newer.Path + ForeignHookRemovalInProgressSuffix, At: at(0), Mark: "linux:b:2000"}
	data, err = EncodeForeignHookRemovals(removals, []ForeignHookRemoval{first}, now)
	if err != nil {
		t.Fatal(err)
	}
	if removals, err = ParseForeignHookRemovals(data); err != nil || len(removals) != 2 {
		t.Fatalf("the first record is kept next to the removal: %+v %v", removals, err)
	}
	moved := first
	moved.At = at(time.Second)
	post := ForeignHookRemoval{Identity: "1001", Connector: "cursor", Path: newer.Path, At: at(time.Second), Mark: "linux:b:1000"}
	data, err = EncodeForeignHookRemovalsDropping(removals, []ForeignHookRemoval{post}, []ForeignHookRemoval{moved}, now)
	if err != nil {
		t.Fatal(err)
	}
	if removals, err = ParseForeignHookRemovals(data); err != nil || len(removals) != 1 || removals[0].Mark != post.Mark || removals[0].Path != post.Path {
		t.Fatalf("the commit must drop its first record and keep its own later mark: %+v %v", removals, err)
	}
}
