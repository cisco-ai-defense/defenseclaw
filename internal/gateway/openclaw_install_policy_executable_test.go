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
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// writeOpenClawDiscoveryAt caches an OpenClaw version read from binaryPath,
// atomically like discovery.
func writeOpenClawDiscoveryAt(t *testing.T, dataDir, version, binaryPath string) {
	t.Helper()
	body, err := json.Marshal(map[string]any{"agents": map[string]any{
		"openclaw": map[string]any{"installed": true, "version": version, "binary_path": binaryPath},
	}})
	if err != nil {
		t.Fatal(err)
	}
	tmp := filepath.Join(dataDir, "agent_discovery.json.tmp")
	if err := os.WriteFile(tmp, body, 0o600); err != nil {
		t.Fatal(err)
	}
	replaceOpenClawDiscoveryFile(t, tmp, filepath.Join(dataDir, "agent_discovery.json"))
}

// openClawExecutableFixture is a registered install policy written under
// OpenClaw 2026.11.3 read from one openclaw executable (recorded in the state
// file unless recordPath is false), a second trusted openclaw on another
// PATH, and a watcher whose refreshes are recorded.
func openClawExecutableFixture(t *testing.T, recordPath bool) (s *Sidecar, dataDir, first, second string, refreshed chan connector.SetupOpts, calls *atomic.Int32) {
	t.Helper()
	resetOpenClawInstallPolicyRetryState(t)
	s, dataDir, _ = registeredOpenClawInstallPolicy(t, "2026.11.3")
	bin := t.TempDir()
	first, second = filepath.Join(bin, "a", "openclaw"), filepath.Join(bin, "b", "openclaw")
	for _, path := range []string{first, second} {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("x"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	state := map[string]string{"state": "registered", "openclaw_version": "2026.11.3", "at": "2026-11-17T00:00:00Z"}
	if recordPath {
		state["openclaw_binary_path"] = first
	}
	data, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dataDir, "openclaw-install-policy-state.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	writeOpenClawDiscoveryAt(t, dataDir, "2026.11.3", first)
	refreshed = make(chan connector.SetupOpts, 64)
	calls = &atomic.Int32{}
	openClawInstallPolicyRefresher = func(opts connector.SetupOpts) (string, error) {
		calls.Add(1)
		refreshed <- opts
		return "registered", nil
	}
	openClawInstallPolicyVersionPoll = 2 * time.Millisecond
	return s, dataDir, first, second, refreshed, calls
}

func waitOpenClawRefresh(t *testing.T, refreshed chan connector.SetupOpts, what string) connector.SetupOpts {
	t.Helper()
	select {
	case opts := <-refreshed:
		return opts
	case <-time.After(5 * time.Second):
		t.Fatalf("%s did not refresh the install policy", what)
	}
	return connector.SetupOpts{}
}

// GAP-1237: doctor run from a shell whose PATH finds another trusted
// openclaw caches its older version. The OpenClaw the policy was written
// under is still installed, so the watcher does not act on it; a version
// change of the executable the policy was written under still refreshes.
// Before, the block was removed within 30 seconds and a run from the other
// shell put it back (flap).
func TestOpenClawInstallPolicyWatchIgnoresAnotherOpenClawOnPATH(t *testing.T) {
	s, dataDir, first, second, refreshed, calls := openClawExecutableFixture(t, true)
	stop := s.startOpenClawInstallPolicyWatch(context.Background())
	defer stop()

	writeOpenClawDiscoveryAt(t, dataDir, "2026.7.1", second)
	// The watcher looks every 2 ms; give it many looks at the other openclaw
	// (the step below proves it is looking).
	time.Sleep(500 * time.Millisecond)
	if n := calls.Load(); n != 0 {
		t.Fatalf("a discovery that found another openclaw on PATH refreshed the install policy %d times", n)
	}
	writeOpenClawDiscoveryAt(t, dataDir, "2026.7.1", first)
	if opts := waitOpenClawRefresh(t, refreshed, "a downgrade of the recorded openclaw"); opts.AgentVersion != "2026.7.1" {
		t.Fatalf("refreshed under %q, want 2026.7.1", opts.AgentVersion)
	}
}

// GAP-1237: the openclaw the policy was written under is gone (reinstalled
// to another folder). The executable the cache names now is the one the user
// runs: a change of executable refreshes, also under the same version, and
// the new executable is what the policy is then written under.
func TestOpenClawInstallPolicyWatchFollowsAReinstallToAnotherFolder(t *testing.T) {
	s, dataDir, first, second, refreshed, _ := openClawExecutableFixture(t, true)
	stop := s.startOpenClawInstallPolicyWatch(context.Background())
	defer stop()

	if err := os.Remove(first); err != nil {
		t.Fatal(err)
	}
	writeOpenClawDiscoveryAt(t, dataDir, "2026.11.3", second)
	opts := waitOpenClawRefresh(t, refreshed, "a reinstall of OpenClaw 2026.11.3 to another folder")
	if opts.AgentVersion != "2026.11.3" || opts.AgentExecutable != second {
		t.Fatalf("refreshed under %q from %q, want 2026.11.3 from %s", opts.AgentVersion, opts.AgentExecutable, second)
	}
	// Written under the new executable now: its downgrade refreshes.
	writeOpenClawDiscoveryAt(t, dataDir, "2026.7.1", second)
	if opts := waitOpenClawRefresh(t, refreshed, "a downgrade of the reinstalled openclaw"); opts.AgentVersion != "2026.7.1" {
		t.Fatalf("refreshed under %q, want 2026.7.1", opts.AgentVersion)
	}
}

// A state file written before the executable was recorded keeps the earlier
// behaviour: any cached version change refreshes.
func TestOpenClawInstallPolicyWatchWithoutARecordedExecutableActsOnEveryVersion(t *testing.T) {
	s, dataDir, _, second, refreshed, _ := openClawExecutableFixture(t, false)
	stop := s.startOpenClawInstallPolicyWatch(context.Background())
	defer stop()
	writeOpenClawDiscoveryAt(t, dataDir, "2026.7.1", second)
	if opts := waitOpenClawRefresh(t, refreshed, "a version change with no recorded executable"); opts.AgentVersion != "2026.7.1" {
		t.Fatalf("refreshed under %q, want 2026.7.1", opts.AgentVersion)
	}
}
