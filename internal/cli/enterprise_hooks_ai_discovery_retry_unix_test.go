//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/inventory"
	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
)

// aiDiscoveryBurstFixture runs the guardian's AI discovery for one home with
// a fake clock. The skill folder in it reads unreadable while the clock is in
// the half-open window [burstStart, burstEnd) (a burst of ctime-only changes)
// and ok before and after; a read is the worker's scan.
type aiDiscoveryBurstFixture struct {
	t                     *testing.T
	dir                   string
	rows                  []enterpriseHookReconcileRow
	t0                    time.Time
	now                   atomic.Int64
	mu                    sync.Mutex
	reads                 []aiDiscoveryBurstRead
	burstStart, burstEnd  time.Time
	permanentlyUnreadable bool
}

type aiDiscoveryBurstRead struct {
	at     time.Duration
	status string
}

func newAIDiscoveryBurstFixture(t *testing.T) *aiDiscoveryBurstFixture {
	t.Helper()
	uid, gid := os.Getuid(), os.Getgid()
	resolver := standaloneTestResolver{accounts: map[string]unixidentity.Account{}}
	f := newStandaloneFixture(t, resolver)
	alice := f.home(t, "alice", 0o700)
	resolver.accounts["alice"] = unixidentity.Account{Name: "alice", UID: uid, GID: gid, Home: alice, Shell: "/bin/bash"}
	for path, body := range map[string]string{
		filepath.Join(".codex", "config.toml"):              "model = \"x\"\n",
		filepath.Join(".claude", "skills", "s", "SKILL.md"): "---\nname: s\n---\nbody\n",
	} {
		full := filepath.Join(alice, path)
		if err := os.MkdirAll(filepath.Dir(full), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	cfg.AIDiscovery.Enabled = true
	cfg.AIDiscovery.ScanIntervalMin = 1
	b := &aiDiscoveryBurstFixture{
		t:    t,
		dir:  inventory.UserScanDirForConfig(cfg),
		rows: []enterpriseHookReconcileRow{{User: "alice", UserHome: alice, Connector: "codex", OK: true, UID: uid}},
		t0:   time.Date(2026, 11, 23, 20, 0, 0, 0, time.UTC),
	}
	b.now.Store(b.t0.UnixNano())

	previousBreaker, previousReader := enterpriseHookAIDiscoveryBreaker, enterpriseHookAIDiscoveryRecordReader
	previousNow, previousWait := enterpriseHookAIDiscoveryNow, enterpriseHookAIDiscoveryWait
	t.Cleanup(func() {
		enterpriseHookAIDiscoveryBreaker, enterpriseHookAIDiscoveryRecordReader = previousBreaker, previousReader
		enterpriseHookAIDiscoveryNow, enterpriseHookAIDiscoveryWait = previousNow, previousWait
		enterpriseHookAIDiscoveryState.Lock()
		enterpriseHookAIDiscoveryState.running, enterpriseHookAIDiscoveryState.last = false, time.Time{}
		enterpriseHookAIDiscoveryState.fingerprint, enterpriseHookAIDiscoveryState.retriesSpent = "", false
		enterpriseHookAIDiscoveryState.Unlock()
	})
	enterpriseHookAIDiscoveryBreaker = newEnterpriseHookScanBreaker(3, time.Hour, 24*time.Hour)
	enterpriseHookAIDiscoveryRecordReader = readTestUserScanRecord
	enterpriseHookAIDiscoveryNow = func() time.Time { return time.Unix(0, b.now.Load()).UTC() }
	enterpriseHookAIDiscoveryWait = func(_ context.Context, d time.Duration) bool {
		b.now.Add(int64(d))
		return true
	}
	enterpriseHookWorkerRunner = func(ctx context.Context, account enterpriseHookWorkerAccount, request enterpriseHookWorkerRequest) (enterpriseHookWorkerResponse, error) {
		options := request.AIDiscovery.Options
		options.DisableSkillContentHashes = false
		report := inventory.ScanUserHome(ctx, account.Home, account.User, account.UID, options, request.AIDiscovery.Catalog)
		at := enterpriseHookAIDiscoveryNow()
		unreadable := b.permanentlyUnreadable || (!at.Before(b.burstStart) && at.Before(b.burstEnd))
		status := inventory.SkillContentOK
		if unreadable {
			status = inventory.SkillContentUnreadable
		}
		seen := false
		for i := range report.Signals {
			for j := range report.Signals[i].Evidence {
				if facts := report.Signals[i].Evidence[j].Skill; facts != nil {
					seen = true
					facts.ContentStatus = status
					if unreadable {
						facts.ContentHash, facts.ManifestHash, facts.ManifestSize = "", "", 0
					}
				}
			}
		}
		if !seen {
			b.t.Error("the scan of the home reported no skill facts; the fixture does not cover a skill folder")
		}
		b.mu.Lock()
		b.reads = append(b.reads, aiDiscoveryBurstRead{at: at.Sub(b.t0), status: status})
		b.mu.Unlock()
		return enterpriseHookWorkerResponse{Version: enterpriseHookWorkerProtocolVersion, AIDiscovery: &report}, nil
	}
	return b
}

// tick is one watch reconcile that reaches the AI discovery step at offset
// from the start, and returns once the pass it started (with its retries) is
// over.
func (b *aiDiscoveryBurstFixture) tick(offset time.Duration) {
	b.t.Helper()
	if b.t0.Add(offset).UnixNano() < b.now.Load() {
		return // the pass of an earlier tick, with its retries, is still running
	}
	b.now.Store(b.t0.Add(offset).UnixNano())
	startEnterpriseHookAIDiscovery(context.Background(), io.Discard, enterpriseHookReconcileRun{Rows: b.rows})
	deadline := time.Now().Add(30 * time.Second)
	for {
		enterpriseHookAIDiscoveryState.Lock()
		running := enterpriseHookAIDiscoveryState.running
		enterpriseHookAIDiscoveryState.Unlock()
		if !running {
			return
		}
		if time.Now().After(deadline) {
			b.t.Fatal("the AI discovery pass did not end")
		}
		runtime.Gosched()
	}
}

func (b *aiDiscoveryBurstFixture) snapshot() []aiDiscoveryBurstRead {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]aiDiscoveryBurstRead(nil), b.reads...)
}

// GAP-2034: a pass that read a skill folder while it changed leaves
// content_status unreadable in the spool; once the folder is stable the next
// read must replace it without waiting for the interval. The reconcile ticks
// come a little less than a minute apart, as they do when one reconcile takes
// longer than the one before it.
func TestStandaloneAIDiscoveryRereadsAnUnreadableSkillOnceItIsStable(t *testing.T) {
	b := newAIDiscoveryBurstFixture(t)
	b.burstStart, b.burstEnd = b.t0.Add(30*time.Second), b.t0.Add(95*time.Second)
	for _, offset := range []time.Duration{0, 60100 * time.Millisecond, 119900 * time.Millisecond, 179900 * time.Millisecond} {
		b.tick(offset)
	}
	var firstOKAfterBurst time.Duration
	for _, read := range b.snapshot() {
		if read.status == inventory.SkillContentOK && read.at >= b.burstEnd.Sub(b.t0) {
			firstOKAfterBurst = read.at
			break
		}
	}
	if firstOKAfterBurst == 0 {
		t.Fatalf("no read after the burst found the skill ok: %+v", b.snapshot())
	}
	if lag := firstOKAfterBurst - b.burstEnd.Sub(b.t0); lag > 40*time.Second {
		t.Fatalf("the skill read ok %s after the burst ended, want within 40s (reads %+v)", lag, b.snapshot())
	}
}

// A tick that reaches the pass a few milliseconds before the interval
// started it from the last pass starts the next one.
func TestStandaloneAIDiscoveryTickJitterDoesNotSkipAPass(t *testing.T) {
	b := newAIDiscoveryBurstFixture(t)
	b.tick(0)
	b.tick(59900 * time.Millisecond)
	if got := len(b.snapshot()); got != 2 {
		t.Fatalf("passes = %d, want 2", got)
	}
	b.tick(65 * time.Second) // five seconds after the last pass: not due
	if got := len(b.snapshot()); got != 2 {
		t.Fatalf("passes = %d after a tick 5s after the last pass, want 2", got)
	}
}

// A skill folder that is never readable costs its retries once, not on
// every pass.
func TestStandaloneAIDiscoveryRetriesAnUnreadableSkillOnlyOnce(t *testing.T) {
	b := newAIDiscoveryBurstFixture(t)
	b.permanentlyUnreadable = true
	b.tick(0)
	if got, want := len(b.snapshot()), 1+len(enterpriseHookAIDiscoveryRetryDelays); got != want {
		t.Fatalf("passes after the first tick = %d, want %d (the pass and its retries)", got, want)
	}
	b.tick(10 * time.Minute)
	if got, want := len(b.snapshot()), 2+len(enterpriseHookAIDiscoveryRetryDelays); got != want {
		t.Fatalf("passes after the second tick = %d, want %d (one pass, no retries)", got, want)
	}
	b.permanentlyUnreadable = false
	b.tick(20 * time.Minute)
	b.permanentlyUnreadable = true
	b.tick(30 * time.Minute)
	if got, want := len(b.snapshot()), 4+2*len(enterpriseHookAIDiscoveryRetryDelays); got != want {
		t.Fatalf("passes after a clean pass and a new failure = %d, want %d (retries again)", got, want)
	}
}
