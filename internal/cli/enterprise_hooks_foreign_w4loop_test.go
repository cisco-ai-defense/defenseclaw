// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/agentprocess"
	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
)

// The last regressions of the W4 sec-sandbox-guard loop (045cdd5c2a), each
// gone by construction in the consolidated design.

// (1) An older cleanup published last must not erase a newer removal. Every
// guardian process merges its records into the ledger under the ledger
// lock, so a writer that read the ledger before another wrote it waits for
// that write and then merges with it: nothing is lost, and per account,
// connector and file the record made last wins (nanosecond times).
func TestForeignHookLedgerWriteFromAnotherProcessIsNeverLost(t *testing.T) {
	skipForeignHookLedgerOnWindows(t)
	g := useForeignHookGuardian(t, nil)
	dir := filepath.Dir(g.ledger)
	mark := agentprocess.Now()
	if mark == "" {
		t.Skip("the process clock is unavailable here")
	}
	// Another guardian process: it holds the ledger lock, reads the
	// ledger, takes its time, and writes the ledger with its own removal.
	other := enterprisepolicy.ForeignHookRemoval{Identity: "1002", Connector: "cursor", Path: "/home/bob/.cursor/hooks.json",
		At: time.Now().UTC().Format(time.RFC3339Nano), Mark: mark}
	release, err := enterprisepolicy.LockForeignHookRemovalLedger(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	existing, err := loadEnterpriseForeignHookRemovals(g.ledger)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		var stderr bytes.Buffer
		recordEnterpriseForeignHookRemovalsAt(&stderr, mark, "1001", t.TempDir(), "cursor", []string{"/home/alice/.cursor/hooks.json"})
		if stderr.Len() != 0 {
			t.Error(stderr.String())
		}
	}()
	time.Sleep(200 * time.Millisecond)
	data, err := enterprisepolicy.EncodeForeignHookRemovals(existing, []enterprisepolicy.ForeignHookRemoval{other}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := writeEnterpriseHookGatewayRecord(g.ledger, data); err != nil {
		t.Fatal(err)
	}
	release()
	wg.Wait()
	if _, ok := g.entry(t, "1002", "cursor", other.Path); !ok {
		t.Fatalf("the other process's removal was lost: %+v", g.removals(t))
	}
	if _, ok := g.entry(t, "1001", "cursor", "/home/alice/.cursor/hooks.json"); !ok {
		t.Fatalf("this process's removal was lost: %+v", g.removals(t))
	}
}

// (2) One account's drain never delays another account's removal: the drain
// waits on that account's own lock only.
func TestForeignHookRemovalOfOneAccountDoesNotWaitForAnothersDrain(t *testing.T) {
	skipForeignHookLedgerOnWindows(t)
	g := useForeignHookGuardian(t, nil)
	_ = g
	// Account 1002 has an online answer that does not finish.
	held, err := enterprisepolicy.LockForeignHookAccountExchange(context.Background(), cfg.DataDir, "1002")
	if err != nil {
		t.Fatal(err)
	}
	defer held()
	start := time.Now()
	var stderr bytes.Buffer
	recordEnterpriseForeignHookRemovalsAt(&stderr, agentprocess.Now(), "1001", t.TempDir(), "cursor", []string{"/home/alice/.cursor/hooks.json"})
	if waited := time.Since(start); waited >= enterprisepolicy.ForeignHookRemovalDrainWait {
		t.Fatalf("account 1001's removal waited %s on account 1002's drain", waited)
	}
	if _, ok := g.entry(t, "1001", "cursor", "/home/alice/.cursor/hooks.json"); !ok {
		t.Fatalf("the removal was not recorded: %s %+v", stderr.String(), g.removals(t))
	}
}

// (3) A contended lock never makes an agent that started after the change
// look old: the mark is taken when the cleanup ended, before any wait.
func TestForeignHookRemovalMarkIsTakenBeforeTheLockWait(t *testing.T) {
	skipForeignHookLedgerOnWindows(t)
	g := useForeignHookGuardian(t, nil)
	mark := agentprocess.Now()
	if mark == "" {
		t.Skip("the process clock is unavailable here")
	}
	release, err := enterprisepolicy.LockForeignHookRemovalLedger(context.Background(), filepath.Dir(g.ledger))
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		var stderr bytes.Buffer
		recordEnterpriseForeignHookRemovalsAt(&stderr, mark, "1001", t.TempDir(), "cursor", []string{"/home/alice/.cursor/hooks.json"})
	}()
	time.Sleep(300 * time.Millisecond)
	// An agent started while the record waited for the lock.
	startedDuringTheWait := foreignHookTestProcessAt(t, agentprocess.Now(), 4242, 0)
	release()
	<-done
	removal, ok := g.entry(t, "1001", "cursor", "/home/alice/.cursor/hooks.json")
	if !ok {
		t.Fatalf("the removal was not recorded: %+v", g.removals(t))
	}
	if removal.Mark != mark {
		t.Fatalf("the record must carry the mark of when the cleanup ended: %q, want %q", removal.Mark, mark)
	}
	if agentprocess.StartedBefore(startedDuringTheWait, removal.Mark) {
		t.Fatal("an agent that started during the lock wait must not count as one that loaded the removed hook")
	}
	if !agentprocess.StartedBefore(foreignHookTestProcessAt(t, mark, 4243, -1), removal.Mark) {
		t.Fatal("an agent that started before the cleanup ended must be denied")
	}
}
