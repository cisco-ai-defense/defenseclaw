// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package gateway

import (
	"context"
	"errors"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/openshell/egress"
	"github.com/defenseclaw/defenseclaw/internal/sandboxrelay"
)

// freshFixture is a daemon with reg-1 for the running dc-a and a relay whose
// policy/current answer the test sets, counting the calls.
type freshFixture struct {
	*sandboxDaemonFixture
	mu     sync.Mutex
	answer sandboxrelay.CurrentPolicy
	err    error
	calls  atomic.Int32
}

func newFreshFixture(t *testing.T) *freshFixture {
	t.Helper()
	f := &freshFixture{answer: sandboxrelay.CurrentPolicy{V: 1, Generation: 7, Digest: "sha256:v1"}}
	f.sandboxDaemonFixture = newSandboxDaemonFixture(t, func(o *SandboxDaemonOptions) {
		o.listPhases = func(context.Context) (map[string]string, bool) { return map[string]string{"dc-a": "ready"}, true }
	})
	if err := f.d.regs.put(daemonRegistration{ID: "reg-1", Sandbox: "dc-a", Digest: "sha256:v1", Generation: 7,
		UpdatedAt: time.Now(), Confirmed: true}); err != nil {
		t.Fatal(err)
	}
	f.relay.current = func(string) (sandboxrelay.CurrentPolicy, error) {
		f.calls.Add(1)
		f.mu.Lock()
		defer f.mu.Unlock()
		return f.answer, f.err
	}
	return f
}

func (f *freshFixture) set(cp sandboxrelay.CurrentPolicy, err error) {
	f.mu.Lock()
	f.answer, f.err = cp, err
	f.mu.Unlock()
}

func (f *freshFixture) confirm() (bool, *egress.Decision) {
	return f.d.confirmEgressPolicy(context.Background(), egress.Principal{BindingID: "binding-a", SandboxName: "dc-a"})
}

func (f *freshFixture) floorBlocks(host string) bool {
	f.d.floorMu.Lock()
	defer f.d.floorMu.Unlock()
	return f.d.floor != nil && slices.Contains(f.d.floor.EgressBlock, host)
}

// GAP-0172: a running managed sandbox kept the old egress lists for 20-50 s
// after ensure reported the administrator's change (a git clone the new
// block forbids ran, a curl after the block was lifted still failed),
// because the daemon learned of the change from a relayed hook or the
// minute's poll only. Its egress proxy now confirms the sandbox's policy
// before a new connection: within a lease nothing is asked; a relayed answer
// that named another generation, or a lease that ran out (a connection no
// hook preceded, as `sandbox exec`), asks policy/current first, and a change
// re-resolves the policy (the floor the manager resolves against) before the
// connection is decided, tightened and loosened alike.
func TestSandboxDaemonEgressConfirmsTheChangedPolicyFirst(t *testing.T) {
	f := newFreshFixture(t)
	if changed, off := f.confirm(); changed || off != nil || f.calls.Load() != 1 {
		t.Fatalf("first connection: changed %v off %v calls %d", changed, off, f.calls.Load())
	}
	if changed, off := f.confirm(); changed || off != nil || f.calls.Load() != 1 {
		t.Fatalf("within the lease: changed %v off %v calls %d", changed, off, f.calls.Load())
	}

	// Tightened: the relayed hook before the clone named another generation.
	f.set(sandboxrelay.CurrentPolicy{V: 1, Generation: 3, Digest: "sha256:v2",
		Live: sandboxrelay.LiveFields{EgressBlock: []string{"github.com"}}}, nil)
	f.d.observeGeneration("reg-1", 3)
	if changed, off := f.confirm(); !changed || off != nil {
		t.Fatalf("tightened: changed %v off %v", changed, off)
	}
	if !f.floorBlocks("github.com") {
		t.Fatalf("the floor did not take the block before the connection: %+v", f.d.floor)
	}
	if r, _ := f.d.regs.get("dc-a"); r.Generation != 3 || r.Digest != "sha256:v2" {
		t.Fatalf("registration = %+v", r)
	}
	calls := f.calls.Load()
	f.d.observeGeneration("reg-1", 3)
	if changed, off := f.confirm(); changed || off != nil || f.calls.Load() != calls {
		t.Fatalf("the same generation again: changed %v off %v calls %d -> %d", changed, off, calls, f.calls.Load())
	}

	// Loosened, under a smaller generation digest.
	f.set(sandboxrelay.CurrentPolicy{V: 1, Generation: 2, Digest: "sha256:v3"}, nil)
	f.d.observeGeneration("reg-1", 2)
	if changed, off := f.confirm(); !changed || off != nil || f.floorBlocks("github.com") {
		t.Fatalf("loosened: changed %v off %v floor %+v", changed, off, f.d.floor)
	}

	// No hook before the connection: the lease runs out and the connection
	// confirms the policy itself.
	f.set(sandboxrelay.CurrentPolicy{V: 1, Generation: 11, Digest: "sha256:v4",
		Live: sandboxrelay.LiveFields{EgressBlock: []string{"github.com"}}}, nil)
	time.Sleep(sandboxEgressLease + 50*time.Millisecond)
	if changed, off := f.confirm(); !changed || off != nil || !f.floorBlocks("github.com") {
		t.Fatalf("after the lease: changed %v off %v floor %+v", changed, off, f.d.floor)
	}
}

// GAP-0172: a managed gateway that does not answer keeps the policy in
// force, as the minute's poll does, unless a relayed answer already said the
// policy changed: then new connections are refused until the new policy is
// confirmed, without asking on every connection, so a tightening never waits
// for the gateway. A registration the gateway ended refuses too and asks for
// the poll that stops its sandbox.
func TestSandboxDaemonEgressRefusesAnUnconfirmedChange(t *testing.T) {
	f := newFreshFixture(t)
	f.set(sandboxrelay.CurrentPolicy{}, errors.New("dial unix: connection refused"))
	if changed, off := f.confirm(); changed || off != nil {
		t.Fatalf("no known change: changed %v off %v", changed, off)
	}
	f.d.observeGeneration("reg-1", 8)
	calls := f.calls.Load()
	for i := 0; i < 2; i++ {
		_, off := f.confirm()
		if off == nil || off.Allowed || off.Category != egress.CategoryEgressOff || off.Source != egress.SourceAdmin ||
			off.Reason != sandboxEgressPolicyChanging {
			t.Fatalf("unconfirmed change, connection %d: %+v", i, off)
		}
	}
	if f.calls.Load() != calls+1 {
		t.Fatalf("calls %d -> %d, want one try within the lease", calls, f.calls.Load())
	}

	f.set(sandboxrelay.CurrentPolicy{V: 1, Generation: 8, Digest: "sha256:v1"}, nil)
	time.Sleep(sandboxEgressLease + 50*time.Millisecond)
	if _, off := f.confirm(); off != nil {
		t.Fatalf("confirmed: off %+v", off)
	}

	select {
	case <-f.d.refresh:
	default:
	}
	f.set(sandboxrelay.CurrentPolicy{V: 1, Generation: 8, Revoked: true, RevokedReason: "policy_changed"}, nil)
	time.Sleep(sandboxEgressLease + 50*time.Millisecond)
	if _, off := f.confirm(); off == nil || off.Category != egress.CategoryEgressOff {
		t.Fatalf("revoked: off %+v", off)
	}
	select {
	case <-f.d.refresh:
	default:
		t.Fatal("a revoked registration did not ask for the poll that stops its sandbox")
	}
}

// GAP-0172 (DELTA-15 verify r2): a burst of new connections while the
// tightened policy is adopted shares one confirmation, and none of them is
// decided under the floor before the change, whether it came in before the
// adoption, during it or after the lease renewed.
func TestSandboxDaemonEgressBurstDuringAdoption(t *testing.T) {
	f := newFreshFixture(t)
	f.confirm()
	var listed atomic.Int32
	f.d.opts.listPhases = func(context.Context) (map[string]string, bool) {
		listed.Add(1)
		time.Sleep(300 * time.Millisecond)
		return map[string]string{"dc-a": "ready"}, true
	}
	f.set(sandboxrelay.CurrentPolicy{V: 1, Generation: 3, Digest: "sha256:v2",
		Live: sandboxrelay.LiveFields{EgressBlock: []string{"github.com"}}}, nil)
	f.d.observeGeneration("reg-1", 3)
	calls := f.calls.Load()
	var wg sync.WaitGroup
	var old, refused atomic.Int32
	for i := 0; i < 24; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			time.Sleep(time.Duration(i%8) * 50 * time.Millisecond)
			_, off := f.confirm()
			switch {
			case off != nil:
				refused.Add(1)
			case !f.floorBlocks("github.com"):
				old.Add(1)
			}
		}(i)
	}
	wg.Wait()
	if old.Load() != 0 || refused.Load() != 0 {
		t.Fatalf("burst: %d connections decided under the old floor, %d refused", old.Load(), refused.Load())
	}
	if got := f.calls.Load() - calls; got != 1 || listed.Load() != 1 {
		t.Fatalf("burst: %d confirmations and %d adoptions, want one each", got, listed.Load())
	}
}

// GAP-0172: a change that another path applied to a registration (the
// minute's poll still asking the others, a start) is in force before the
// next connection of any running sandbox is decided, also one whose own
// lease is fresh: the floor the manager resolves against is the newest
// running registration's.
func TestSandboxDaemonEgressAdoptsAChangeAppliedElsewhere(t *testing.T) {
	f := newFreshFixture(t)
	f.d.opts.listPhases = func(context.Context) (map[string]string, bool) {
		return map[string]string{"dc-a": "ready", "dc-b": "ready"}, true
	}
	if err := f.d.regs.put(daemonRegistration{ID: "reg-2", Sandbox: "dc-b", Digest: "sha256:v1", Generation: 7,
		UpdatedAt: time.Now().Add(-time.Hour), Confirmed: true}); err != nil {
		t.Fatal(err)
	}
	f.confirm()
	calls := f.calls.Load()
	r2, _ := f.d.regs.get("dc-b")
	if !f.d.regs.applyOrdered(r2, f.d.regs.nextSeq(), sandboxrelay.CurrentPolicy{V: 1, Generation: 4, Digest: "sha256:v2",
		UpdatedAt: time.Now(), Live: sandboxrelay.LiveFields{EgressBlock: []string{"github.com"}}}) {
		t.Fatal("the change was not applied")
	}
	if changed, off := f.confirm(); !changed || off != nil || !f.floorBlocks("github.com") {
		t.Fatalf("dc-a after dc-b's change: changed %v off %v floor %+v", changed, off, f.d.floor)
	}
	if f.calls.Load() != calls {
		t.Fatalf("a fresh lease asked policy/current: %d -> %d", calls, f.calls.Load())
	}
	// Sandboxes that can't be listed leave the change out of force: refused.
	f.d.opts.listPhases = func(context.Context) (map[string]string, bool) { return nil, false }
	f.d.regs.applyLive("dc-b", sandboxrelay.CurrentPolicy{V: 1, Generation: 5, Digest: "sha256:v3", UpdatedAt: time.Now()})
	if _, off := f.confirm(); off == nil || off.Reason != sandboxEgressPolicyChanging {
		t.Fatalf("unlisted: off %+v", off)
	}
}

// GAP-0172: an answer to a policy request older than one already applied for
// the registration changes nothing (a start's state report racing the
// minute's poll), nor does one for a registration the sandbox's name no
// longer holds.
func TestSandboxDaemonRegistrationsDropAnOlderAnswer(t *testing.T) {
	f := newFreshFixture(t)
	r, _ := f.d.regs.get("dc-a")
	older, newer := f.d.regs.nextSeq(), f.d.regs.nextSeq()
	block := sandboxrelay.CurrentPolicy{V: 1, Generation: 3, Digest: "sha256:v2",
		Live: sandboxrelay.LiveFields{EgressBlock: []string{"github.com"}}}
	if !f.d.regs.applyOrdered(r, newer, block) {
		t.Fatal("the newer answer was not applied")
	}
	if f.d.regs.applyOrdered(r, older, sandboxrelay.CurrentPolicy{V: 1, Generation: 7, Digest: "sha256:v1"}) {
		t.Fatal("the older answer was applied")
	}
	if got, _ := f.d.regs.get("dc-a"); got.Generation != 3 || got.Digest != "sha256:v2" || len(got.Floor.EgressBlock) != 1 {
		t.Fatalf("registration after the older answer = %+v", got)
	}
	if f.d.regs.applyOrdered(daemonRegistration{ID: "reg-old", Sandbox: "dc-a"}, f.d.regs.nextSeq(), sandboxrelay.CurrentPolicy{V: 1, Digest: "sha256:v9"}) {
		t.Fatal("an answer for another registration of the name was applied")
	}
}

// Codex F1 (DELTA-15 review): a registration the daemon marked revoked
// refuses its sandbox's new connections at once, without asking the
// gateway, although its sandbox's stop may have failed and the proxy still
// holds its credential.
func TestSandboxDaemonEgressRefusesARevokedRegistration(t *testing.T) {
	f := newFreshFixture(t)
	f.confirm()
	calls := f.calls.Load()
	f.d.regs.markRevoked("dc-a", "policy_changed")
	_, off := f.confirm()
	if off == nil || off.Category != egress.CategoryEgressOff || off.Source != egress.SourceAdmin || off.Reason != sandboxEgressNotCovered {
		t.Fatalf("revoked: off %+v", off)
	}
	if f.calls.Load() != calls {
		t.Fatalf("a revoked registration asked policy/current: %d -> %d", calls, f.calls.Load())
	}
	// A sandbox a create has not registered yet keeps the create's floor.
	if _, off := f.d.confirmEgressPolicy(context.Background(), egress.Principal{BindingID: "binding-n", SandboxName: "dc-new"}); off != nil {
		t.Fatalf("unregistered: off %+v", off)
	}
}

// Codex F10 (DELTA-15 review): the poll drops the lease and the request
// order of a registration the daemon no longer has.
func TestSandboxDaemonEgressLeasesGoWithTheirRegistration(t *testing.T) {
	f := newFreshFixture(t)
	f.confirm()
	if err := f.d.regs.put(daemonRegistration{ID: "reg-gone", Sandbox: "dc-gone", Confirmed: true}); err != nil {
		t.Fatal(err)
	}
	gone, _ := f.d.regs.get("dc-gone")
	f.d.leases.lease("reg-gone")
	f.d.regs.applyOrdered(gone, f.d.regs.nextSeq(), sandboxrelay.CurrentPolicy{V: 1})
	if err := f.d.regs.drop("dc-gone"); err != nil {
		t.Fatal(err)
	}
	f.d.pollRegistrations(context.Background(), true)
	f.d.leases.mu.Lock()
	_, leased := f.d.leases.byID["reg-gone"]
	_, kept := f.d.leases.byID["reg-1"]
	f.d.leases.mu.Unlock()
	f.d.regs.mu.Lock()
	_, ordered := f.d.regs.applied["reg-gone"]
	f.d.regs.mu.Unlock()
	if leased || ordered || !kept {
		t.Fatalf("after the poll: lease of the dropped registration %v, its order %v, live lease %v", leased, ordered, kept)
	}
}

// leaseFresh reports whether id's egress lease decides a new connection
// without asking (egressLeases.begin's fresh rule), with no side effect.
func (f *freshFixture) leaseFresh(id string) bool {
	lease := f.d.leases.lease(id)
	f.d.leases.mu.Lock()
	defer f.d.leases.mu.Unlock()
	changing := !lease.stale.IsZero() && !lease.confirmed.After(lease.stale)
	return !lease.gone && !changing && !lease.confirmed.IsZero() && time.Since(lease.confirmed) < sandboxEgressLease
}

// GAP-0172 (DELTA-15 verify r2, item 1): a connection's confirmation renews
// the lease only once the answer is in force. Renewed before the adoption,
// the next connection's lease said fresh while the floor still had the old
// lists.
func TestSandboxDaemonEgressLeaseRenewsAfterTheAdoption(t *testing.T) {
	f := newFreshFixture(t)
	f.confirm()
	adopting := make(chan struct{})
	f.d.opts.listPhases = func(context.Context) (map[string]string, bool) {
		close(adopting)
		time.Sleep(300 * time.Millisecond)
		return map[string]string{"dc-a": "ready"}, true
	}
	f.set(sandboxrelay.CurrentPolicy{V: 1, Generation: 3, Digest: "sha256:v2",
		Live: sandboxrelay.LiveFields{EgressBlock: []string{"github.com"}}}, nil)
	f.d.observeGeneration("reg-1", 3)
	done := make(chan struct{})
	go func() { f.confirm(); close(done) }()
	<-adopting
	time.Sleep(50 * time.Millisecond)
	if f.leaseFresh("reg-1") {
		t.Fatal("the lease renewed before the adoption")
	}
	<-done
	if !f.leaseFresh("reg-1") || !f.floorBlocks("github.com") {
		t.Fatalf("after the adoption: lease fresh %v, floor %+v", f.leaseFresh("reg-1"), f.d.floor)
	}
}

// GAP-0172 (DELTA-15 verify r2, item 2): the poll renews the leases it
// confirmed only once its adoption returned: between its loop and its
// adoption (here held in the settings read a moved generation makes), the
// lease of the registration whose answer moved the policy is not fresh,
// and is once the poll adopted it.
func TestSandboxDaemonEgressPollRenewsAfterTheAdoption(t *testing.T) {
	f := newFreshFixture(t)
	f.confirm()
	reading, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	f.relay.settings = func() (sandboxrelay.DaemonSettings, error) {
		once.Do(func() { close(reading) })
		<-release
		return f.d.currentSettings(), nil
	}
	f.set(sandboxrelay.CurrentPolicy{V: 1, Generation: 3, Digest: "sha256:v2", UpdatedAt: time.Now(),
		Live: sandboxrelay.LiveFields{EgressBlock: []string{"github.com"}}}, nil)
	f.d.observeGeneration("reg-1", 3)
	pollDone := make(chan struct{})
	go func() { f.d.pollRegistrations(context.Background(), true); close(pollDone) }()
	<-reading
	if r, _ := f.d.regs.get("dc-a"); r.Generation != 3 {
		t.Fatalf("the poll's loop did not apply the answer: %+v", r)
	}
	if f.leaseFresh("reg-1") || f.floorBlocks("github.com") {
		t.Fatalf("before the adoption: lease fresh %v, floor %+v", f.leaseFresh("reg-1"), f.d.floor)
	}
	close(release)
	<-pollDone
	if !f.leaseFresh("reg-1") || !f.floorBlocks("github.com") {
		t.Fatalf("after the poll: lease fresh %v, floor %+v", f.leaseFresh("reg-1"), f.d.floor)
	}
}

// Codex F6 (DELTA-15 review): a confirmation the managed gateway kept for the
// whole timeout is tried again a lease after it ended, not after it began, so
// the connections right after it do not each wait for one more.
func TestSandboxDaemonEgressRetriesALeaseAfterAFailedConfirmationEnded(t *testing.T) {
	f := newFreshFixture(t)
	f.relay.current = func(string) (sandboxrelay.CurrentPolicy, error) {
		f.calls.Add(1)
		time.Sleep(sandboxEgressConfirmTimeout + 50*time.Millisecond)
		return sandboxrelay.CurrentPolicy{}, errors.New("context deadline exceeded")
	}
	if _, off := f.confirm(); off != nil {
		t.Fatalf("no known change, gateway hung: off %+v", off)
	}
	start := time.Now()
	if _, off := f.confirm(); off != nil || f.calls.Load() != 1 || time.Since(start) > sandboxEgressLease/2 {
		t.Fatalf("right after: off %+v calls %d took %v", off, f.calls.Load(), time.Since(start))
	}
}

// GAP-0172: a connection that comes in after a relayed hook named another
// generation does not take the outcome of a confirmation asked for before
// that: it waits for it, then for one asked for after the change.
func TestSandboxDaemonEgressAConnectionAfterTheChangeWaitsForANewerConfirmation(t *testing.T) {
	f := newFreshFixture(t)
	newA := sandboxrelay.CurrentPolicy{V: 1, Generation: 3, Digest: "sha256:v2",
		Live: sandboxrelay.LiveFields{EgressBlock: []string{"github.com"}}}
	f.relay.current = func(string) (sandboxrelay.CurrentPolicy, error) {
		if f.calls.Add(1) == 1 {
			time.Sleep(300 * time.Millisecond)
			return sandboxrelay.CurrentPolicy{V: 1, Generation: 7, Digest: "sha256:v1"}, nil
		}
		return newA, nil
	}
	done := make(chan struct{})
	go func() { f.confirm(); close(done) }()
	time.Sleep(100 * time.Millisecond)
	f.d.observeGeneration("reg-1", 3)
	time.Sleep(50 * time.Millisecond)
	_, off := f.confirm()
	<-done
	if off == nil && !f.floorBlocks("github.com") {
		t.Fatal("the connection after the change took a confirmation asked for before it")
	}
	if f.calls.Load() != 2 {
		t.Fatalf("confirmations %d, want 2", f.calls.Load())
	}
}

// GAP-0172: a relayed hook can name a tightened generation while the first
// connection's policy/current is still in flight. Its older answer must not
// let that connection through under the old lists, even if no second
// connection arrives to notice that the lease remained stale.
func TestSandboxDaemonEgressInFlightAnswerAfterChangeIsRetried(t *testing.T) {
	f := newFreshFixture(t)
	firstAsked := make(chan struct{})
	releaseFirst := make(chan struct{})
	f.relay.current = func(string) (sandboxrelay.CurrentPolicy, error) {
		if f.calls.Add(1) == 1 {
			close(firstAsked)
			<-releaseFirst
			return sandboxrelay.CurrentPolicy{V: 1, Generation: 7, Digest: "sha256:v1"}, nil
		}
		return sandboxrelay.CurrentPolicy{V: 1, Generation: 3, Digest: "sha256:v2",
			Live: sandboxrelay.LiveFields{EgressBlock: []string{"github.com"}}}, nil
	}
	done := make(chan *egress.Decision, 1)
	go func() {
		_, off := f.confirm()
		done <- off
	}()
	<-firstAsked
	f.d.observeGeneration("reg-1", 3)
	close(releaseFirst)
	off := <-done
	if off == nil && !f.floorBlocks("github.com") {
		t.Fatal("the in-flight old answer let the connection through after the change was named")
	}
	if off == nil && f.calls.Load() != 2 {
		t.Fatalf("admitted after %d policy requests, want a new confirmation", f.calls.Load())
	}
}
