// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// The 1.0.4 guard consolidation: one kill switch (record key) per account
// and one writer-preferred removal lock per account. These tests drive the
// gateway's online exchange (handleForeignHookSession) against the lock and
// the key, with the guardian's side played by the enterprisepolicy APIs.

// setForeignHookExchangeWaitForTest bounds how long an exchange waits for
// its account's removal lock.
func setForeignHookExchangeWaitForTest(t *testing.T, wait time.Duration) {
	t.Helper()
	previous := foreignHookExchangeWait
	foreignHookExchangeWait = wait
	t.Cleanup(func() { foreignHookExchangeWait = previous })
}

// setForeignHookExchangeHoldForTest bounds how long after taking its
// account's lock an exchange may still answer allow.
func setForeignHookExchangeHoldForTest(t *testing.T, hold time.Duration) {
	t.Helper()
	previous := foreignHookExchangeHold
	foreignHookExchangeHold = hold
	t.Cleanup(func() { foreignHookExchangeHold = previous })
}

// foreignHookTestCall is a guarded call of process in session that the
// scan allows (sessionStart: the agent's session start).
func foreignHookTestCall(session, process string, sessionStart bool) map[string]any {
	return map[string]any{"key": map[string]any{"connector": "claudecode", "session": session, "process": process},
		"session_start": sessionStart, "decision": map[string]any{"deny": false}}
}

// timedForeignHookResponse records when the handler's body write returned.
type timedForeignHookResponse struct {
	deadlineRecorder
	mu      sync.Mutex
	written time.Time
}

func (w *timedForeignHookResponse) Write(data []byte) (int, error) {
	n, err := w.deadlineRecorder.Write(data)
	w.mu.Lock()
	w.written = time.Now()
	w.mu.Unlock()
	return n, err
}

func (w *timedForeignHookResponse) writtenAt() time.Time {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.written
}

// foreignHookRemovalAttempt is one guardian removal of an account: when its
// LockForeignHookAccountRemoval returned and what it returned.
type foreignHookRemovalAttempt struct {
	release func()
	drained bool
	err     error
	at      time.Time
}

func startForeignHookRemoval(t *testing.T, dataDir, identity string, timeout time.Duration) <-chan foreignHookRemovalAttempt {
	t.Helper()
	out := make(chan foreignHookRemovalAttempt, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		release, drained, err := enterprisepolicy.LockForeignHookAccountRemoval(ctx, dataDir, identity)
		out <- foreignHookRemovalAttempt{release: release, drained: drained, err: err, at: time.Now()}
	}()
	return out
}

// pausedForeignHookExchange is an exchange of alice that stopped inside
// her account's lock: in the record key read ("key") or in the protected
// record write of its allow ("publish").
type pausedForeignHookExchange struct {
	server   *foreignHookPublishTestServer
	writes   *[]foreignHookPublished
	response *timedForeignHookResponse
	entered  chan struct{}
	resume   func()
	done     chan struct{}
}

func startPausedForeignHookExchange(t *testing.T, at string) *pausedForeignHookExchange {
	t.Helper()
	var mu sync.Mutex
	var writes []foreignHookPublished
	entered := make(chan struct{})
	resumed := make(chan struct{})
	enter := sync.OnceFunc(func() { close(entered) })
	p := &pausedForeignHookExchange{writes: &writes, entered: entered, resume: sync.OnceFunc(func() { close(resumed) }), done: make(chan struct{})}
	t.Cleanup(p.resume)
	var server *foreignHookPublishTestServer
	server = newForeignHookPublishTestServer(t, func(r, identity string, key enterprisepolicy.SessionKey, decision enterprisepolicy.GuardDecision, recordKey enterprisepolicy.SessionRecordKey, _ time.Time) error {
		mu.Lock()
		writes = append(writes, foreignHookPublished{r, identity, key, decision.Deny, recordKey.ID()})
		mu.Unlock()
		if at == "publish" && identity == server.alice && !decision.Deny {
			enter()
			<-resumed
		}
		return nil
	})
	if at == "key" {
		previousKey := foreignHookSessionKey
		foreignHookSessionKey = func(r, identity string) (enterprisepolicy.SessionRecordKey, error) {
			key, err := previousKey(r, identity)
			if identity == server.alice {
				enter()
				<-resumed
			}
			return key, err
		}
	}
	p.server = server
	p.response = &timedForeignHookResponse{deadlineRecorder: newDeadlineRecorder()}
	go func() {
		defer close(p.done)
		server.direct(p.response, server.alice, foreignHookTestCall("s-1", runtime.GOOS+":b:1:500", false))
	}()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("the exchange did not reach its pause")
	}
	return p
}

func (p *pausedForeignHookExchange) finish(t *testing.T) {
	t.Helper()
	p.resume()
	select {
	case <-p.done:
	case <-time.After(5 * time.Second):
		t.Fatal("the exchange did not finish")
	}
}

// GAP-0348, GAP-0414 (a): while the guardian removes a hook of the account
// (it holds the account's removal lock), every exchange of the account is
// denied, with the removal's own reason unless the scan itself blocks, and
// only the denial is published, after the account's key is gone. Another
// account is answered as before, and the account is decided normally once
// the removal is done.
func TestForeignHookAccountRemovalInProgressDeniesTheAccount(t *testing.T) {
	setForeignHookExchangeWaitForTest(t, 50*time.Millisecond)
	process := runtime.GOOS + ":b:1:500"
	const pending = "DefenseClaw is removing an unapproved hook from your account"
	for _, tc := range []struct {
		name   string
		update map[string]any
		reason string
		blocks bool // the session start recorded a block that outlives the removal
	}{
		{"a tool call the scan allows", foreignHookTestCall("s-1", process, false), pending, false},
		{"a clean session start", foreignHookTestCall("s-1", process, true), pending, false},
		{"a session start that finds a hook", foreignHookPublishTestBlock("s-1", process), "project hook", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var writes []foreignHookPublished
			server := newForeignHookPublishTestServer(t, foreignHookRecorder(&writes, nil))
			bobKey := server.keyID(server.bob)
			release, drained, err := lockForeignHookAccountRemovalForTest(t, server.dataDir, server.alice, time.Second)
			if err != nil || !drained {
				t.Fatalf("take the removal lock: drained %v, %v", drained, err)
			}
			t.Cleanup(release)
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
			_, lockErr := foreignHookAccountExchangeLock(ctx, server.dataDir, server.alice)
			cancel()
			if !errors.Is(lockErr, enterprisepolicy.ErrForeignHookRemovalPending) {
				t.Fatalf("the exchange lock during a removal = %v, want ErrForeignHookRemovalPending", lockErr)
			}

			got := server.call(server.aliceToken, tc.update)
			if !got.Deny || !strings.Contains(got.Reason, tc.reason) {
				t.Fatalf("an exchange during a removal of the account: %+v, want a denial naming %q", got, tc.reason)
			}
			if tc.reason == pending && (len(got.Findings) == 0 || got.Findings[0].Reason != "a hook removal is in progress") {
				t.Fatalf("the pending denial names the removal first: %+v", got.Findings)
			}
			if len(writes) != 1 || !writes[0].deny || writes[0].keyID != "" || writes[0].identity != server.alice {
				t.Fatalf("only the denial is published, without a key: %+v", writes)
			}
			if server.keyID(server.alice) != "" {
				t.Fatal("the denial is published only after the account's key is gone")
			}

			// Another account is answered as before, with its own key.
			if got := server.call(server.bobToken, foreignHookTestCall("s-b", process, false)); got.Deny {
				t.Fatalf("another account during the removal: %+v", got)
			}
			if last := writes[len(writes)-1]; last.identity != server.bob || last.deny || last.keyID != bobKey {
				t.Fatalf("another account's allow carries its key %s: %+v", bobKey, last)
			}

			release()
			server.newKey(server.alice)
			if got := server.call(server.aliceToken, foreignHookTestCall("s-9", process, false)); got.Deny != tc.blocks {
				t.Fatalf("after the removal (no hook recorded for the account): %+v, want deny %v", got, tc.blocks)
			}
		})
	}
}

// GAP-0348, GAP-0414 (b): an exchange that holds its account's lock is
// finished before a removal of the account gets the lock, or is cut: its
// allow is written before the removal holds the lock; an allow it could no
// longer write within foreignHookExchangeHold of taking the lock is refused;
// a decision taken past the hold is a denial, published after the key is
// gone; and an exchange still inside when the removal stops waiting
// (ForeignHookRemovalDrainWait) has its allow refused, and the allow record
// it published carries the key the removal rotated away.
func TestForeignHookAccountRemovalWaitsForTheExchangeInside(t *testing.T) {
	t.Run("an allow written within its hold", func(t *testing.T) {
		p := startPausedForeignHookExchange(t, "publish")
		removal := startForeignHookRemoval(t, p.server.dataDir, p.server.alice, 5*time.Second)
		select {
		case got := <-removal:
			if got.release != nil {
				got.release()
			}
			t.Fatalf("the removal got the lock while an allow was inside: %+v", got)
		case <-time.After(100 * time.Millisecond):
		}
		p.finish(t)
		if p.response.Code != http.StatusOK || !strings.Contains(p.response.Body.String(), `"deny":false`) {
			t.Fatalf("the allow inside the lock: %d %s", p.response.Code, p.response.Body.String())
		}
		got := <-removal
		if got.err != nil || !got.drained {
			t.Fatalf("the removal after the allow: drained %v, %v", got.drained, got.err)
		}
		got.release()
		if written := p.response.writtenAt(); written.IsZero() || !written.Before(got.at) {
			t.Fatalf("the allow was written at %v, the removal held the lock at %v", written, got.at)
		}
	})

	t.Run("an allow whose write would pass its hold is refused", func(t *testing.T) {
		setForeignHookExchangeHoldForTest(t, 300*time.Millisecond)
		p := startPausedForeignHookExchange(t, "publish")
		removal := startForeignHookRemoval(t, p.server.dataDir, p.server.alice, 5*time.Second)
		time.Sleep(450 * time.Millisecond)
		select {
		case got := <-removal:
			t.Fatalf("the removal got the lock while the exchange was inside: %+v", got)
		default:
		}
		p.finish(t)
		if body := p.response.Body.String(); p.response.Code != http.StatusServiceUnavailable || !strings.Contains(body, "foreign_hook_removal_fence_expired") || strings.Contains(body, `"deny":false`) {
			t.Fatalf("an allow past its hold: %d %s", p.response.Code, body)
		}
		got := <-removal
		if got.err != nil || !got.drained {
			t.Fatalf("the removal after the refusal: drained %v, %v", got.drained, got.err)
		}
		got.release()
	})

	t.Run("a decision past its hold is a denial", func(t *testing.T) {
		setForeignHookExchangeHoldForTest(t, 300*time.Millisecond)
		p := startPausedForeignHookExchange(t, "key")
		removal := startForeignHookRemoval(t, p.server.dataDir, p.server.alice, 5*time.Second)
		time.Sleep(450 * time.Millisecond)
		p.finish(t)
		if body := p.response.Body.String(); p.response.Code != http.StatusOK || !strings.Contains(body, `"deny":true`) || !strings.Contains(body, "cannot verify this agent session") {
			t.Fatalf("a decision past its hold: %d %s", p.response.Code, body)
		}
		got := <-removal
		if got.err != nil || !got.drained {
			t.Fatalf("the removal after the denial: drained %v, %v", got.drained, got.err)
		}
		got.release()
		if writes := *p.writes; len(writes) != 1 || !writes[0].deny || writes[0].keyID != "" || p.server.keyID(p.server.alice) != "" {
			t.Fatalf("the denial is published after the key is gone: %+v (key %q)", writes, p.server.keyID(p.server.alice))
		}
	})

	t.Run("an exchange the removal stopped waiting for is cut", func(t *testing.T) {
		p := startPausedForeignHookExchange(t, "publish")
		before := p.server.keyID(p.server.alice)
		started := time.Now()
		removal := startForeignHookRemoval(t, p.server.dataDir, p.server.alice, 10*time.Second)
		var got foreignHookRemovalAttempt
		select {
		case got = <-removal:
		case <-time.After(enterprisepolicy.ForeignHookRemovalDrainWait + 3*time.Second):
			t.Fatal("the removal waited past its drain wait")
		}
		if got.err != nil || got.drained || got.at.Sub(started) < enterprisepolicy.ForeignHookRemovalDrainWait-50*time.Millisecond {
			t.Fatalf("the removal went on after %v: drained %v, %v", got.at.Sub(started), got.drained, got.err)
		}
		// The guardian rotates the account's key first.
		if err := enterprisepolicy.RotatePublishedSessionKey(p.server.root, p.server.alice, foreignHookTestTrust); err != nil {
			t.Fatal(err)
		}
		got.release()
		p.finish(t)
		if body := p.response.Body.String(); p.response.Code != http.StatusServiceUnavailable || !strings.Contains(body, "foreign_hook_removal_fence_expired") || strings.Contains(body, `"deny":false`) {
			t.Fatalf("an allow the removal stopped waiting for: %d %s", p.response.Code, body)
		}
		writes := *p.writes
		if len(writes) != 1 || writes[0].deny || writes[0].keyID != before || before == "" || p.server.keyID(p.server.alice) == before {
			t.Fatalf("the allow record carries the key the removal rotated away (%s, now %s): %+v", before, p.server.keyID(p.server.alice), writes)
		}
	})
}

// GAP-0348, GAP-0414 (c): one account's removal never delays another
// account: during it the other account's exchange is answered at once
// while the removed account's waits its bounded wait and is denied, and an
// exchange inside one account's lock never delays a removal of another.
func TestForeignHookAccountRemovalNeverDelaysAnotherAccount(t *testing.T) {
	var mu sync.Mutex
	var writes []foreignHookPublished
	entered := make(chan struct{})
	resumed := make(chan struct{})
	enter, resume := sync.OnceFunc(func() { close(entered) }), sync.OnceFunc(func() { close(resumed) })
	t.Cleanup(resume)
	pause := false
	var server *foreignHookPublishTestServer
	server = newForeignHookPublishTestServer(t, func(r, identity string, key enterprisepolicy.SessionKey, decision enterprisepolicy.GuardDecision, recordKey enterprisepolicy.SessionRecordKey, _ time.Time) error {
		mu.Lock()
		writes = append(writes, foreignHookPublished{r, identity, key, decision.Deny, recordKey.ID()})
		paused := pause && identity == server.alice && !decision.Deny
		mu.Unlock()
		if paused {
			enter()
			<-resumed
		}
		return nil
	})
	carol := foreignHookTestIdentities(3)[2]
	process := runtime.GOOS + ":b:1:500"
	exchange := func(identity, session string) (*timedForeignHookResponse, time.Duration) {
		t.Helper()
		response := &timedForeignHookResponse{deadlineRecorder: newDeadlineRecorder()}
		started := time.Now()
		server.direct(response, identity, foreignHookTestCall(session, process, false))
		return response, time.Since(started)
	}
	denied := func(r *timedForeignHookResponse) bool {
		return r.Code == http.StatusOK && strings.Contains(r.Body.String(), `"deny":true`)
	}
	allowed := func(r *timedForeignHookResponse) bool {
		return r.Code == http.StatusOK && strings.Contains(r.Body.String(), `"deny":false`)
	}

	// Alice's removal holds her lock: bob is answered at once, alice waits
	// her bounded wait and is denied.
	release, drained, err := lockForeignHookAccountRemovalForTest(t, server.dataDir, server.alice, time.Second)
	if err != nil || !drained {
		t.Fatalf("take alice's removal lock: drained %v, %v", drained, err)
	}
	t.Cleanup(release)
	if response, took := exchange(server.bob, "s-b1"); !allowed(response) || took >= foreignHookExchangeWait {
		t.Fatalf("bob's exchange during alice's removal took %v: %d %s", took, response.Code, response.Body.String())
	}
	if response, took := exchange(server.alice, "s-a1"); !denied(response) || !strings.Contains(response.Body.String(), "is removing an unapproved hook") || took < foreignHookExchangeWait {
		t.Fatalf("alice's exchange during her removal took %v: %d %s", took, response.Code, response.Body.String())
	}
	release()

	// Alice's allow is inside her lock: bob's removal drains at once, and
	// during it carol is allowed and bob denied.
	mu.Lock()
	pause = true
	mu.Unlock()
	aliceResponse := &timedForeignHookResponse{deadlineRecorder: newDeadlineRecorder()}
	aliceDone := make(chan struct{})
	go func() {
		defer close(aliceDone)
		server.direct(aliceResponse, server.alice, foreignHookTestCall("s-a2", process, false))
	}()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("alice's allow did not reach its pause")
	}
	asked := time.Now()
	releaseBob, drained, err := lockForeignHookAccountRemovalForTest(t, server.dataDir, server.bob, 3*time.Second)
	if took := time.Since(asked); err != nil || !drained || took >= foreignHookExchangeHold/2 {
		t.Fatalf("bob's removal behind alice's allow took %v: drained %v, %v", took, drained, err)
	}
	t.Cleanup(releaseBob)
	if response, took := exchange(carol, "s-c1"); !allowed(response) || took >= foreignHookExchangeWait {
		t.Fatalf("carol's exchange during bob's removal took %v: %d %s", took, response.Code, response.Body.String())
	}
	if response, _ := exchange(server.bob, "s-b2"); !denied(response) || !strings.Contains(response.Body.String(), "is removing an unapproved hook") {
		t.Fatalf("bob's exchange during his removal: %d %s", response.Code, response.Body.String())
	}
	releaseBob()
	resume()
	<-aliceDone
	if !allowed(aliceResponse) {
		t.Fatalf("alice's allow: %d %s", aliceResponse.Code, aliceResponse.Body.String())
	}
}

// Round-3 P1 #1, 1.0.4 guard loop round 1: a standalone gateway whose data
// directory names no record folder still records a session start's block
// in its private store and denies the call; it publishes nothing and
// removes no key (it never published an allow either). Where the folder is
// named, every call of the blocked process is still denied (the block is
// sticky), and the account's key, only that account's, is removed before
// the denial is published.
func TestForeignHookSessionWithoutARecordFolderStillRecordsTheBlock(t *testing.T) {
	var writes []foreignHookPublished
	server := newForeignHookPublishTestServer(t, foreignHookRecorder(&writes, nil))
	var kills []string
	previousKill := foreignHookSessionKill
	foreignHookSessionKill = func(r, identity string) error {
		kills = append(kills, r+"|"+identity)
		return previousKill(r, identity)
	}
	foreignHookSessionRootForDataDir = func(string) (string, bool) { return "", false }
	process := runtime.GOOS + ":b:1:500"
	if got := server.call(server.aliceToken, foreignHookPublishTestBlock("s-1", process)); !got.Deny || !strings.Contains(got.Reason, "project hook") {
		t.Fatalf("the session start that found the hook: %+v", got)
	}
	for _, record := range []string{
		foreignHookTestStoreRecord(server.dataDir, server.alice, "claudecode", "p", process),
		foreignHookTestStoreRecord(server.dataDir, server.alice, "claudecode", "s", "s-1"),
	} {
		if _, err := os.Lstat(record); err != nil {
			t.Fatalf("the block is in the private store: %v", err)
		}
	}
	if len(writes) != 0 || len(kills) != 0 {
		t.Fatalf("without a record folder nothing is published or removed: %+v %v", writes, kills)
	}

	foreignHookSessionRootForDataDir = func(string) (string, bool) { return server.root, true }
	bobKey := server.keyID(server.bob)
	for _, session := range []string{"s-1", "s-2"} {
		kills = nil
		if got := server.call(server.aliceToken, foreignHookTestCall(session, process, false)); !got.Deny || !strings.Contains(got.Reason, "restart the agent") {
			t.Fatalf("a call of the blocked process (%s) where the folder is named: %+v", session, got)
		}
		if len(kills) != 1 || kills[0] != server.root+"|"+server.alice || server.keyID(server.alice) != "" || server.keyID(server.bob) != bobKey {
			t.Fatalf("the blocked account's key, and only its key, is removed: %v", kills)
		}
		if last := writes[len(writes)-1]; !last.deny || last.keyID != "" || last.identity != server.alice {
			t.Fatalf("the block is published after the kill: %+v", writes)
		}
		server.newKey(server.alice)
	}
}

// Round-3 P1 #2: the session start that records a block removes the
// account's key before the block is written to the private store
// (SessionUpdate.BeforeBlock), and publishes the block only after that. A
// key that cannot be removed is tried again before the block is published,
// and the block is still recorded and published (it denies during an
// outage). Every later denial of the account removes its key again.
func TestForeignHookSessionBlockKillsTheAccountKeyBeforeTheStoreWrite(t *testing.T) {
	for _, tc := range []struct {
		name    string
		killErr error
		block   []string // the events of the session start that records the block
		later   []string // the events of a later call of the blocked process
		keyGone bool
	}{
		{"the kill works", nil,
			[]string{"kill (store empty)", "publish deny"},
			[]string{"kill (store has the block)", "publish deny"}, true},
		{"the kill and its revocation mark fail", fmt.Errorf("%w: read-only file system", enterprisepolicy.ErrPublishedSessionKeyAlive),
			[]string{"kill failed (store empty)", "kill failed (store has the block)", "publish deny"},
			[]string{"kill failed (store has the block)", "publish deny"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var events []string
			server := newForeignHookPublishTestServer(t, func(_, _ string, _ enterprisepolicy.SessionKey, decision enterprisepolicy.GuardDecision, _ enterprisepolicy.SessionRecordKey, _ time.Time) error {
				events = append(events, map[bool]string{true: "publish deny", false: "publish allow"}[decision.Deny])
				return nil
			})
			process := runtime.GOOS + ":b:1:500"
			blocked := foreignHookTestStoreRecord(server.dataDir, server.alice, "claudecode", "p", process)
			previousKill := foreignHookSessionKill
			foreignHookSessionKill = func(r, identity string) error {
				state := "store empty"
				if _, err := os.Lstat(blocked); err == nil {
					state = "store has the block"
				} else if !errors.Is(err, fs.ErrNotExist) {
					t.Error(err)
				}
				if identity != server.alice {
					t.Errorf("killed the key of %s, want %s", identity, server.alice)
				}
				if tc.killErr != nil {
					events = append(events, "kill failed ("+state+")")
					return tc.killErr
				}
				events = append(events, "kill ("+state+")")
				return previousKill(r, identity)
			}
			bobKey := server.keyID(server.bob)
			if got := server.call(server.aliceToken, foreignHookPublishTestBlock("s-1", process)); !got.Deny {
				t.Fatalf("the session start that found the hook: %+v", got)
			}
			if strings.Join(events, ",") != strings.Join(tc.block, ",") {
				t.Fatalf("block events %v, want %v", events, tc.block)
			}
			if _, err := os.Lstat(blocked); err != nil {
				t.Fatalf("the block is in the private store: %v", err)
			}
			if (server.keyID(server.alice) == "") != tc.keyGone || server.keyID(server.bob) != bobKey {
				t.Fatalf("alice's key %q (gone: want %v), bob's %q (want %q)", server.keyID(server.alice), tc.keyGone, server.keyID(server.bob), bobKey)
			}
			events = nil
			server.newKey(server.alice)
			if got := server.call(server.aliceToken, foreignHookTestCall("s-2", process, false)); !got.Deny {
				t.Fatalf("a later call of the blocked process: %+v", got)
			}
			// The block is carried to the new session: the write runs the
			// kill first, which (when it failed) is tried again after. A
			// kill that failed is owed, so the exchange tries it once more
			// before anything else.
			later := tc.later
			if tc.killErr != nil {
				later = append([]string{"kill failed (store has the block)", "kill failed (store has the block)"}, later...)
			}
			if strings.Join(events, ",") != strings.Join(later, ",") {
				t.Fatalf("later events %v, want %v", events, later)
			}
			if (server.keyID(server.alice) == "") != tc.keyGone {
				t.Fatalf("alice's new key after a later denial: %q (gone: want %v)", server.keyID(server.alice), tc.keyGone)
			}
		})
	}
}

// An account whose removal lock cannot be taken for another reason than a
// removal in progress (here a lock file that is a folder) is denied as
// unverifiable, not as a pending removal: the gateway cannot know a
// removal does not run. Only the denial is published, after the key is
// gone; another account is not affected.
func TestForeignHookAccountLockUnavailableDeniesTheExchange(t *testing.T) {
	for _, tc := range []struct {
		name string
		pick func(gate, lock string) string
	}{
		{"the gate is a folder", func(gate, _ string) string { return gate }},
		{"the lock is a folder", func(_, lock string) string { return lock }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var writes []foreignHookPublished
			server := newForeignHookPublishTestServer(t, foreignHookRecorder(&writes, nil))
			gate, lock, ok := enterprisepolicy.ForeignHookAccountLockPaths(server.dataDir, server.alice)
			if !ok {
				t.Fatal("alice has no removal lock")
			}
			if err := os.MkdirAll(tc.pick(gate, lock), 0o700); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			_, lockErr := foreignHookAccountExchangeLock(ctx, server.dataDir, server.alice)
			cancel()
			if lockErr == nil || errors.Is(lockErr, enterprisepolicy.ErrForeignHookRemovalPending) {
				t.Fatalf("the exchange lock = %v, want an error that is not a pending removal", lockErr)
			}
			process := runtime.GOOS + ":b:1:500"
			got := server.call(server.aliceToken, foreignHookTestCall("s-1", process, false))
			if !got.Deny || !strings.Contains(got.Reason, "cannot verify this agent session's hook record") || strings.Contains(got.Reason, "is removing") {
				t.Fatalf("an exchange whose lock is unavailable: %+v", got)
			}
			if len(writes) != 1 || !writes[0].deny || writes[0].keyID != "" || server.keyID(server.alice) != "" {
				t.Fatalf("only the denial is published, after the key is gone: %+v (key %q)", writes, server.keyID(server.alice))
			}
			if got := server.call(server.bobToken, foreignHookTestCall("s-1", process, false)); got.Deny {
				t.Fatalf("another account: %+v", got)
			}
		})
	}
}

// Only a standalone gateway serves the session exchange, takes the
// account's removal lock and bounds an allow by foreignHookExchangeHold. A
// per-user gateway and a Secure Client gateway answer 404 before they read
// the call, so they take no lock, make no lock file, publish nothing,
// remove no key and refuse nothing for being slow.
func TestForeignHookSessionNonStandaloneGatewayTakesNoAccountLock(t *testing.T) {
	for _, tc := range []struct {
		name    string
		profile string // "" for a per-user (unmanaged) gateway
	}{
		{"a per-user gateway", ""},
		{"a Secure Client gateway", managed.ProfileSecureClient},
	} {
		t.Run(tc.name, func(t *testing.T) {
			foreignHookGuardianDirForTest(t)
			setForeignHookExchangeHoldForTest(t, 0)
			api, _, _ := newUserScopedTestServer(t, false, &userScopedTestLedger{}, nil)
			if tc.profile != "" {
				api.scannerCfg.DeploymentMode = "managed_enterprise"
				api.scannerCfg.Enterprise.Profile = tc.profile
				if !api.scannerCfg.SecureClientIntegration() {
					t.Fatal("the test gateway is not a Secure Client gateway")
				}
			}
			previousLock, previousPublish, previousKill := foreignHookAccountExchangeLock, foreignHookSessionPublish, foreignHookSessionKill
			t.Cleanup(func() {
				foreignHookAccountExchangeLock, foreignHookSessionPublish, foreignHookSessionKill = previousLock, previousPublish, previousKill
			})
			var calls []string
			foreignHookAccountExchangeLock = func(ctx context.Context, dataDir, identity string) (func(), error) {
				calls = append(calls, "lock")
				return previousLock(ctx, dataDir, identity)
			}
			foreignHookSessionPublish = func(string, string, enterprisepolicy.SessionKey, enterprisepolicy.GuardDecision, enterprisepolicy.SessionRecordKey, time.Time) error {
				calls = append(calls, "publish")
				return nil
			}
			foreignHookSessionKill = func(string, string) error {
				calls = append(calls, "kill")
				return nil
			}
			dataDir := api.configDataDir()
			identity := foreignHookTestIdentities(1)[0]
			response := newDeadlineRecorder()
			api.handleForeignHookSession(response, foreignHookAllowRequest(identity, "s-1"))
			if response.Code != http.StatusNotFound {
				t.Fatalf("the session exchange of a non-standalone gateway: %d %s", response.Code, response.Body.String())
			}
			if len(calls) != 0 {
				t.Fatalf("a non-standalone gateway took the lock, published or removed a key: %v", calls)
			}
			gate, lock, ok := enterprisepolicy.ForeignHookAccountLockPaths(dataDir, identity)
			if !ok {
				t.Fatal("no lock paths")
			}
			for _, path := range []string{gate, lock} {
				if _, err := os.Lstat(path); !errors.Is(err, fs.ErrNotExist) {
					t.Fatalf("a non-standalone gateway made the lock file %s: %v", path, err)
				}
			}
		})
	}
}
