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
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

func writeOpenClawDiscoveryVersion(t *testing.T, dataDir, version string) {
	t.Helper()
	body := `{"agents":{"openclaw":{"installed":true,"version":"` + version + `"}}}`
	if err := os.WriteFile(filepath.Join(dataDir, "agent_discovery.json"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func resetOpenClawInstallPolicyRetryState(t *testing.T) {
	t.Helper()
	prevRefresher, prevDelays, prevPoll := openClawInstallPolicyRefresher, openClawInstallPolicyRetryDelays, openClawInstallPolicyVersionPoll
	t.Cleanup(func() {
		openClawInstallPolicyRefresher, openClawInstallPolicyRetryDelays, openClawInstallPolicyVersionPoll = prevRefresher, prevDelays, prevPoll
		stopOpenClawInstallPolicyRetries()
		openClawInstallPolicyStopped.Store(false)
		openClawInstallPolicyPending.Store(false)
		openClawInstallPolicyRetrying.Store(false)
	})
}

// GAP-1198: setup registered the install policy under OpenClaw 2026.11.3
// below a hardened Windows root; OpenClaw is then reinstalled as 2026.8.35.
// Nothing changed in config, so the reload refresh never ran. A change of the
// cached OpenClaw version now re-runs the install policy check, from the
// version the cache holds now; an unchanged version does not.
func TestOpenClawInstallPolicyWatchRefreshesOnACachedVersionChange(t *testing.T) {
	resetOpenClawInstallPolicyRetryState(t)
	dir := t.TempDir()
	writeOpenClawDiscoveryVersion(t, dir, "2026.11.3")
	var calls atomic.Int32
	versions := make(chan string, 8)
	openClawInstallPolicyRefresher = func(opts connector.SetupOpts) (string, error) {
		calls.Add(1)
		versions <- opts.AgentVersion
		return "not registered: too old", nil
	}
	openClawInstallPolicyVersionPoll = 5 * time.Millisecond
	s := &Sidecar{}
	s.cfgCurrent.Store(openClawInstallPolicyTestConfig(t, dir, "on"))

	stop := s.startOpenClawInstallPolicyWatch(context.Background())
	time.Sleep(60 * time.Millisecond)
	if calls.Load() != 0 {
		stop()
		t.Fatalf("an unchanged OpenClaw version refreshed the install policy %d times", calls.Load())
	}
	writeOpenClawDiscoveryVersion(t, dir, "2026.8.35")
	select {
	case got := <-versions:
		if got != "2026.8.35" {
			t.Errorf("the refresh was written from OpenClaw %q, want the cached 2026.8.35", got)
		}
	case <-time.After(5 * time.Second):
		stop()
		t.Fatal("a downgraded OpenClaw did not re-run the install policy check")
	}
	stop()
}

// GAP-1198: a host whose openclaw connector is not guarded does not touch
// openclaw.json because its cached version changed.
func TestOpenClawInstallPolicyWatchIgnoresAnUnguardedHost(t *testing.T) {
	resetOpenClawInstallPolicyRetryState(t)
	dir := t.TempDir()
	writeOpenClawDiscoveryVersion(t, dir, "2026.11.3")
	var calls atomic.Int32
	openClawInstallPolicyRefresher = func(connector.SetupOpts) (string, error) { calls.Add(1); return "ok", nil }
	openClawInstallPolicyVersionPoll = 5 * time.Millisecond
	cfg := openClawInstallPolicyTestConfig(t, dir, "on")
	cfg.Guardrail.Connector = "codex"
	s := &Sidecar{}
	s.cfgCurrent.Store(cfg)
	stop := s.startOpenClawInstallPolicyWatch(context.Background())
	writeOpenClawDiscoveryVersion(t, dir, "2026.8.35")
	time.Sleep(100 * time.Millisecond)
	stop()
	if calls.Load() != 0 {
		t.Fatalf("a host without the openclaw connector refreshed the install policy %d times", calls.Load())
	}
}

// Review r3 (P4): the retry timer of a failed refresh stops with the
// gateway. Before, the AfterFunc stayed armed after ctx was cancelled and
// fired a refresh into a gateway that was gone.
func TestOpenClawInstallPolicyRetryTimerStopsAtShutdown(t *testing.T) {
	resetOpenClawInstallPolicyRetryState(t)
	dir := t.TempDir()
	var calls atomic.Int32
	openClawInstallPolicyRefresher = func(connector.SetupOpts) (string, error) {
		calls.Add(1)
		return "", errors.New("lock_busy")
	}
	openClawInstallPolicyRetryDelays = []time.Duration{40 * time.Millisecond, 40 * time.Millisecond}
	openClawInstallPolicyVersionPoll = time.Hour
	s := &Sidecar{}
	s.cfgCurrent.Store(openClawInstallPolicyTestConfig(t, dir, "on"))

	ctx, cancel := context.WithCancel(context.Background())
	stop := s.startOpenClawInstallPolicyWatch(ctx)
	s.refreshOpenClawInstallPolicy()
	if calls.Load() != 1 || !openClawInstallPolicyRetrying.Load() {
		t.Fatalf("the failed refresh did not arm a retry: calls=%d retrying=%v", calls.Load(), openClawInstallPolicyRetrying.Load())
	}
	cancel()
	stop()
	if openClawInstallPolicyRetrying.Load() {
		t.Fatal("a retry timer is still armed after the gateway stopped")
	}
	openClawInstallPolicyRetryTimerMu.Lock()
	armed := openClawInstallPolicyRetryTimer != nil
	openClawInstallPolicyRetryTimerMu.Unlock()
	if armed {
		t.Fatal("the retry timer was not released at shutdown")
	}
	time.Sleep(200 * time.Millisecond)
	if calls.Load() != 1 {
		t.Fatalf("a retry fired after shutdown: %d refreshes", calls.Load())
	}
	// The refresh is still owed, so a restarted gateway's first reload retries it.
	if !openClawInstallPolicyPending.Load() {
		t.Fatal("stopping must not forget an owed refresh")
	}
	// Nothing is scheduled once the gateway is stopping.
	s.refreshOpenClawInstallPolicy()
	time.Sleep(100 * time.Millisecond)
	if calls.Load() != 2 {
		t.Fatalf("a refresh after shutdown scheduled a retry: %d refreshes", calls.Load())
	}
}
