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
	"context"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// waitForOpenClawRefreshCalls polls calls until it reaches want or the
// deadline passes, and returns the last count.
func waitForOpenClawRefreshCalls(calls *atomic.Int32, want int32, within time.Duration) int32 {
	deadline := time.Now().Add(within)
	for calls.Load() < want && time.Now().Before(deadline) {
		time.Sleep(2 * time.Millisecond)
	}
	return calls.Load()
}

// GAP-1234: a refresh that returned before it looked at the OpenClaw
// version ("not changed: ...", no error) does not move the version the
// policy was written under, so the watcher asks again at its next look and
// the downgrade is judged once a refresh does look. Before, written-under
// moved on any refresh without an error and the watcher never looked again
// for that version.
func TestOpenClawInstallPolicyWatchAsksAgainAfterARefreshThatDecidedNothing(t *testing.T) {
	resetOpenClawInstallPolicyRetryState(t)
	dir := t.TempDir()
	writeOpenClawDiscoveryVersion(t, dir, "2026.11.3")
	var calls atomic.Int32
	versions := make(chan string, 64)
	openClawInstallPolicyRefresher = func(opts connector.SetupOpts) (string, error) {
		versions <- opts.AgentVersion
		if calls.Add(1) == 1 {
			return "not changed: no openclaw.json yet", nil
		}
		return "not registered: too old", nil
	}
	openClawInstallPolicyVersionPoll = 5 * time.Millisecond
	s := &Sidecar{}
	s.cfgCurrent.Store(openClawInstallPolicyTestConfig(t, dir, "on"))
	stop := s.startOpenClawInstallPolicyWatch(context.Background())
	defer stop()

	writeOpenClawDiscoveryVersion(t, dir, "2026.8.34")
	if got := waitForOpenClawRefreshCalls(&calls, 2, 5*time.Second); got < 2 {
		t.Fatalf("after a refresh that decided nothing the watcher did not ask again (%d refreshes)", got)
	}
	for i := 0; i < 2; i++ {
		if got := <-versions; got != "2026.8.34" {
			t.Fatalf("refresh %d judged under %q, want 2026.8.34", i+1, got)
		}
	}
	// The second refresh decided: the watcher is quiet again.
	time.Sleep(80 * time.Millisecond)
	if got := calls.Load(); got != 2 {
		t.Fatalf("the watcher kept refreshing after a refresh decided (%d refreshes)", got)
	}
}

// GAP-1234: an install policy state file that is there but cannot be read
// says nothing about the version the policy was written under, so the
// watcher refreshes at the first version that parses. Before, the read
// error read as "no state" and the cached version was taken for the one the
// policy was written under, so a downgrade cached before the start was
// never judged.
func TestOpenClawInstallPolicyWatchRefreshesWhenTheStateFileCannotBeRead(t *testing.T) {
	resetOpenClawInstallPolicyRetryState(t)
	dir := t.TempDir()
	writeOpenClawDiscoveryVersion(t, dir, "2026.8.34")
	if err := os.Mkdir(filepath.Join(dir, "openclaw-install-policy-state.json"), 0o700); err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	versions := make(chan string, 64)
	openClawInstallPolicyRefresher = func(opts connector.SetupOpts) (string, error) {
		calls.Add(1)
		versions <- opts.AgentVersion
		return "not registered: too old", nil
	}
	openClawInstallPolicyVersionPoll = 5 * time.Millisecond
	s := &Sidecar{}
	s.cfgCurrent.Store(openClawInstallPolicyTestConfig(t, dir, "on"))
	stop := s.startOpenClawInstallPolicyWatch(context.Background())
	defer stop()
	select {
	case got := <-versions:
		if got != "2026.8.34" {
			t.Fatalf("judged under %q, want 2026.8.34", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("an unreadable state file was taken for a policy written under the cached version: nothing was judged")
	}
}
