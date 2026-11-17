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
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// GAP-1237 review: a config reload while the cache names another openclaw
// on PATH (doctor ran from another shell) judges under the openclaw the
// policy was written under. Before, the reload adopted the other one, wrote
// it into the state file, and the watcher then ignored the real one for good.
func TestOpenClawInstallPolicyReloadDoesNotAdoptAnotherOpenClawOnPATH(t *testing.T) {
	s, dataDir, first, second, refreshed, _ := openClawExecutableFixture(t, true)
	stop := s.startOpenClawInstallPolicyWatch(context.Background())
	defer stop()
	writeOpenClawDiscoveryAt(t, dataDir, "2026.7.1", second)
	s.refreshOpenClawInstallPolicy()
	opts := waitOpenClawRefresh(t, refreshed, "the config reload")
	if opts.AgentVersion != "2026.11.3" || opts.AgentExecutable != first {
		t.Fatalf("the reload judged under %q from %q, want 2026.11.3 from the recorded %s", opts.AgentVersion, opts.AgentExecutable, first)
	}
}

// GAP-1237 review: an upgrade in place removes the recorded openclaw for a
// moment (npm rewrites the shim). One look that finds it gone does not hand
// the policy to another openclaw a stale cache names; the watcher needs it
// gone on openClawInstallPolicyGoneLooks looks in a row.
func TestOpenClawInstallPolicyWatchNeedsTheRecordedOpenClawGoneOnLooksInARow(t *testing.T) {
	s, dataDir, first, second, refreshed, calls := openClawExecutableFixture(t, true)
	openClawInstallPolicyGoneLooks = 1 << 30
	stop := s.startOpenClawInstallPolicyWatch(context.Background())
	defer stop()
	if err := os.Remove(first); err != nil {
		t.Fatal(err)
	}
	writeOpenClawDiscoveryAt(t, dataDir, "2026.7.1", second)
	time.Sleep(300 * time.Millisecond)
	if n := calls.Load(); n != 0 {
		t.Fatalf("the watcher followed another openclaw before the recorded one stayed gone (%d refreshes)", n)
	}
	// The watcher is looking: the recorded openclaw back with another
	// version refreshes.
	if err := os.WriteFile(first, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeOpenClawDiscoveryAt(t, dataDir, "2026.7.1", first)
	if opts := waitOpenClawRefresh(t, refreshed, "a downgrade of the recorded openclaw"); opts.AgentExecutable != first {
		t.Fatalf("refreshed from %q, want %s", opts.AgentExecutable, first)
	}
}

// GAP-1237 review r2: a reload decides under 2026.12.1 of the recorded
// openclaw while the watcher last saw 2026.11.3; then a cache from another
// openclaw on PATH arrives and another reload runs. It judges under
// 2026.12.1, what the policy was last written under, not under the older
// version the watcher saw (that could be below 2026.8.35 and remove the
// block).
func TestOpenClawInstallPolicyReloadAfterADecidedReloadDoesNotGoBackToAnOlderSeenVersion(t *testing.T) {
	s, dataDir, first, second, refreshed, _ := openClawExecutableFixture(t, true)
	stop := s.startOpenClawInstallPolicyWatch(context.Background())
	// No watcher from here: only reloads move what was written and seen.
	stop()
	if got := openClawInstallPolicySeen().version; got != "2026.11.3" {
		t.Fatalf("last seen %q at the start, want the recorded 2026.11.3", got)
	}
	writeOpenClawDiscoveryAt(t, dataDir, "2026.12.1", first)
	s.refreshOpenClawInstallPolicy()
	if opts := waitOpenClawRefresh(t, refreshed, "the first reload"); opts.AgentVersion != "2026.12.1" {
		t.Fatalf("the first reload judged under %q, want 2026.12.1", opts.AgentVersion)
	}
	writeOpenClawDiscoveryAt(t, dataDir, "2026.7.1", second)
	s.refreshOpenClawInstallPolicy()
	opts := waitOpenClawRefresh(t, refreshed, "the second reload")
	if opts.AgentVersion != "2026.12.1" || opts.AgentExecutable != first {
		t.Fatalf("the reload after a cache from another openclaw judged under %q from %q, want 2026.12.1 from %s", opts.AgentVersion, opts.AgentExecutable, first)
	}
}

// GAP-1237 review r2: a cache that names no executable does not drop the
// recorded one: a refresh that decides under it keeps it recorded, so
// another openclaw on PATH is still told apart afterwards.
func TestOpenClawInstallPolicyCacheWithoutAnExecutableKeepsTheRecordedOne(t *testing.T) {
	s, dataDir, first, _, refreshed, _ := openClawExecutableFixture(t, true)
	stop := s.startOpenClawInstallPolicyWatch(context.Background())
	defer stop()
	writeOpenClawDiscoveryVersion(t, dataDir, "2026.12.1")
	if opts := waitOpenClawRefresh(t, refreshed, "a version change in a cache without an executable"); opts.AgentExecutable != first {
		t.Fatalf("refreshed with executable %q, want the recorded %s", opts.AgentExecutable, first)
	}
}

// GAP-1237 review: a setup outside the watch (the CLI) records another
// openclaw in the state file; the watcher follows it, so that openclaw's
// version change refreshes and the old one's does not.
func TestOpenClawInstallPolicyWatchFollowsASetupThatRecordsAnotherOpenClaw(t *testing.T) {
	s, dataDir, first, second, refreshed, calls := openClawExecutableFixture(t, true)
	stop := s.startOpenClawInstallPolicyWatch(context.Background())
	defer stop()
	data, err := json.Marshal(map[string]string{
		"state": "registered", "openclaw_version": "2026.11.3", "openclaw_binary_path": second, "at": "2026-11-17T01:00:00Z",
	})
	if err != nil {
		t.Fatal(err)
	}
	statePath := filepath.Join(dataDir, "openclaw-install-policy-state.json")
	tmp := statePath + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		t.Fatal(err)
	}
	replaceOpenClawDiscoveryFile(t, tmp, statePath)
	deadline := time.Now().Add(5 * time.Second)
	for openClawInstallPolicyWritten().binaryPath != second && time.Now().Before(deadline) {
		time.Sleep(2 * time.Millisecond)
	}
	if got := openClawInstallPolicyWritten().binaryPath; got != second {
		t.Fatalf("the watcher did not follow the state file the setup wrote (written under %q)", got)
	}
	// The old openclaw is still there: its downgrade is now another one's.
	writeOpenClawDiscoveryAt(t, dataDir, "2026.7.1", first)
	time.Sleep(300 * time.Millisecond)
	if n := calls.Load(); n != 0 {
		t.Fatalf("a cache from the openclaw setup no longer records refreshed the policy (%d refreshes)", n)
	}
	writeOpenClawDiscoveryAt(t, dataDir, "2026.7.1", second)
	if opts := waitOpenClawRefresh(t, refreshed, "a downgrade of the openclaw setup recorded"); opts.AgentExecutable != second {
		t.Fatalf("refreshed from %q, want %s", opts.AgentExecutable, second)
	}
}
