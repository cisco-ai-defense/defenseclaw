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

package gateway

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

func openClawInstallPolicyTestConfig(t *testing.T, dataDir, policy string) *config.Config {
	t.Helper()
	cfg := &config.Config{DataDir: dataDir}
	cfg.Guardrail.Enabled = true
	cfg.Guardrail.Connector = "openclaw"
	cfg.Connectors.OpenClaw.InstallPolicy = policy
	return cfg
}

// GAP-1128: a reload that turns the OpenClaw install admission on (guardrail
// use-pack strict with install_policy auto, here install_policy on) writes
// it now, not at the next setup; a reload that changes nothing for it, or a
// host without the openclaw connector, does not touch openclaw.json.
func TestRefreshOpenClawInstallPolicyFollowsReload(t *testing.T) {
	prev := openClawInstallPolicyRefresher
	t.Cleanup(func() { openClawInstallPolicyRefresher = prev })
	var calls []connector.SetupOpts
	openClawInstallPolicyRefresher = func(opts connector.SetupOpts) (string, error) {
		calls = append(calls, opts)
		return "registered", nil
	}
	dir := t.TempDir()
	off, on := openClawInstallPolicyTestConfig(t, dir, "off"), openClawInstallPolicyTestConfig(t, dir, "on")
	if openClawInstallPolicyNeedsRefresh(off, off) {
		t.Fatal("an unchanged install admission must not be rewritten")
	}
	if !openClawInstallPolicyNeedsRefresh(off, on) || !openClawInstallPolicyNeedsRefresh(on, off) {
		t.Fatal("turning install admission on or off must refresh it")
	}
	other := openClawInstallPolicyTestConfig(t, dir, "on")
	other.Guardrail.Connector = "codex"
	if openClawInstallPolicyNeedsRefresh(off, other) {
		t.Fatal("a host without the openclaw connector must not touch openclaw.json")
	}
	s := &Sidecar{}
	s.cfgCurrent.Store(on)
	s.refreshOpenClawInstallPolicy()
	if len(calls) != 1 || !calls[0].OpenClawInstallPolicy || calls[0].DataDir != dir {
		t.Fatalf("turning install admission on must rewrite it from the current config: %+v", calls)
	}
	s.cfgCurrent.Store(off)
	s.refreshOpenClawInstallPolicy()
	if len(calls) != 2 || calls[1].OpenClawInstallPolicy {
		t.Fatalf("turning install admission off must remove it: %+v", calls)
	}
}

// GAP-1128 round 2: two quick reloads (strict -> default -> strict). The
// refresh of the first is still writing when the next reloads land; the
// refreshes run one at a time and each writes from the config the gateway
// holds when it runs, so the admission ends on, not on the older off.
func TestRefreshOpenClawInstallPolicyQuickReloadsEndOnTheLatest(t *testing.T) {
	prev := openClawInstallPolicyRefresher
	t.Cleanup(func() { openClawInstallPolicyRefresher = prev })
	dir := t.TempDir()
	on, off := openClawInstallPolicyTestConfig(t, dir, "on"), openClawInstallPolicyTestConfig(t, dir, "off")
	var (
		mu       sync.Mutex
		applied  []bool
		inflight atomic.Int32
		maxIn    atomic.Int32
	)
	firstEntered, releaseFirst := make(chan struct{}), make(chan struct{})
	var first sync.Once
	openClawInstallPolicyRefresher = func(opts connector.SetupOpts) (string, error) {
		n := inflight.Add(1)
		defer inflight.Add(-1)
		if n > maxIn.Load() {
			maxIn.Store(n)
		}
		isFirst := false
		first.Do(func() { isFirst = true })
		if isFirst {
			close(firstEntered)
			<-releaseFirst
		}
		mu.Lock()
		applied = append(applied, opts.OpenClawInstallPolicy)
		mu.Unlock()
		return "ok", nil
	}
	s := &Sidecar{}
	var wg sync.WaitGroup
	refresh := func() { wg.Add(1); go func() { defer wg.Done(); s.refreshOpenClawInstallPolicy() }() }

	s.cfgCurrent.Store(on) // reload 1: strict
	refresh()
	<-firstEntered
	s.cfgCurrent.Store(off) // reload 2: default
	refresh()
	s.cfgCurrent.Store(on) // reload 3: strict
	refresh()
	time.Sleep(50 * time.Millisecond)
	close(releaseFirst)
	wg.Wait()

	if maxIn.Load() != 1 {
		t.Fatalf("refreshes ran concurrently (%d at once)", maxIn.Load())
	}
	if len(applied) != 3 || !applied[len(applied)-1] {
		t.Fatalf("applied %v: the last refresh must write the current (strict, on) config", applied)
	}
}

// GAP-1128 round 3: a refresh that fails (here the openclaw.json lock held
// past its wait) is retried; the retry ends registered and clears the debt.
// When every retry fails, the next reload refreshes again even though it
// changes nothing for the install policy.
func TestRefreshOpenClawInstallPolicyRetriesAFailedRefresh(t *testing.T) {
	prevRefresher, prevDelays := openClawInstallPolicyRefresher, openClawInstallPolicyRetryDelays
	t.Cleanup(func() {
		openClawInstallPolicyRefresher, openClawInstallPolicyRetryDelays = prevRefresher, prevDelays
		openClawInstallPolicyPending.Store(false)
		openClawInstallPolicyRetrying.Store(false)
	})
	errLockBusy := errors.New("lock_busy")
	openClawInstallPolicyRetryDelays = []time.Duration{time.Millisecond, time.Millisecond}
	dir := t.TempDir()
	on := openClawInstallPolicyTestConfig(t, dir, "on")
	s := &Sidecar{}
	s.cfgCurrent.Store(on)

	var calls atomic.Int32
	done := make(chan string, 4)
	openClawInstallPolicyRefresher = func(connector.SetupOpts) (string, error) {
		if calls.Add(1) == 1 {
			return "", fmt.Errorf("%w: openclaw.json.lock held by another process for 10s", errLockBusy)
		}
		done <- "registered"
		return "registered", nil
	}
	s.refreshOpenClawInstallPolicy()
	if !openClawInstallPolicyPending.Load() {
		t.Fatal("a failed refresh must stay owed")
	}
	select {
	case state := <-done:
		if state != "registered" {
			t.Fatalf("retry state %q", state)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("the failed refresh was not retried (%d calls)", calls.Load())
	}
	deadline := time.Now().Add(5 * time.Second)
	for openClawInstallPolicyPending.Load() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if openClawInstallPolicyPending.Load() || calls.Load() != 2 {
		t.Fatalf("after the retry: pending=%v calls=%d", openClawInstallPolicyPending.Load(), calls.Load())
	}

	// Every retry fails: still owed, and the next reload asks again.
	calls.Store(0)
	openClawInstallPolicyRefresher = func(connector.SetupOpts) (string, error) {
		calls.Add(1)
		return "", errLockBusy
	}
	s.refreshOpenClawInstallPolicy()
	deadline = time.Now().Add(5 * time.Second)
	for calls.Load() < 3 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	time.Sleep(20 * time.Millisecond)
	if calls.Load() != 3 || !openClawInstallPolicyPending.Load() {
		t.Fatalf("exhausted retries: calls=%d (want 1 + 2 retries) pending=%v", calls.Load(), openClawInstallPolicyPending.Load())
	}
	if openClawInstallPolicyNeedsRefresh(on, on) || !openClawInstallPolicyReloadWanted(on, on) {
		t.Fatal("a reload must refresh an owed install policy even when it changes nothing for it")
	}
}
