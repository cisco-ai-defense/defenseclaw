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
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// openClawRegisteredBlock stands for the security.installPolicy setup wrote;
// the refresh compares it with its record, not with what it would write now.
const openClawRegisteredBlock = `{"enabled":true,"targets":["skill","plugin"],"exec":{"source":"exec","command":"/opt/defenseclaw/bin/defenseclaw-gateway","args":["connector","openclaw","install-policy"]}}`

// registeredOpenClawInstallPolicy is an OpenClaw home where setup registered
// the DefenseClaw install policy under OpenClaw version, and a sidecar with
// install_policy on whose refresh runs the real connector.
func registeredOpenClawInstallPolicy(t *testing.T, version string) (s *Sidecar, dataDir, configPath string) {
	t.Helper()
	dataDir, home := t.TempDir(), t.TempDir()
	configPath = filepath.Join(home, "openclaw.json")
	files := map[string]string{
		configPath: `{"security":{"installPolicy":` + openClawRegisteredBlock + `}}`,
		filepath.Join(dataDir, "openclaw-install-policy.json"):       `{"block":` + openClawRegisteredBlock + `,"security_before":false}`,
		filepath.Join(dataDir, "openclaw-install-policy-state.json"): `{"state":"registered","openclaw_version":"` + version + `","at":"2026-11-17T00:00:00Z"}`,
	}
	for path, body := range files {
		if err := os.WriteFile(path, []byte(body+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	writeOpenClawDiscoveryVersion(t, dataDir, version)
	cfg := openClawInstallPolicyTestConfig(t, dataDir, "on")
	cfg.Claw.HomeDir = home
	s = &Sidecar{}
	s.cfgCurrent.Store(cfg)
	return s, dataDir, configPath
}

func openClawInstallPolicyStillRegistered(t *testing.T, configPath string) bool {
	t.Helper()
	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Security map[string]json.RawMessage `json:"security"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("openclaw.json: %v\n%s", err, data)
	}
	_, ok := doc.Security["installPolicy"]
	return ok
}

// GAP-1198 review (P2), path a: a refresh fails (the openclaw.json lock is
// busy) and its retry fires while the cache reads "" (discovery ran while
// openclaw was replaced). An unknown version is no evidence that OpenClaw is
// too old; before, it read as "not wanted" and the retry removed the
// registered policy, so installs skipped DefenseClaw (fail-open).
func TestOpenClawInstallPolicyRetryUnderAnUnknownVersionKeepsThePolicy(t *testing.T) {
	resetOpenClawInstallPolicyRetryState(t)
	s, dataDir, configPath := registeredOpenClawInstallPolicy(t, "2026.11.3")
	real := openClawInstallPolicyRefresher
	var calls atomic.Int32
	done := make(chan error, 4)
	openClawInstallPolicyRetryDelays = []time.Duration{time.Millisecond}
	openClawInstallPolicyRefresher = func(opts connector.SetupOpts) (string, error) {
		if calls.Add(1) == 1 {
			writeOpenClawDiscoveryVersion(t, dataDir, "")
			return "", errors.New("lock_busy")
		}
		state, err := real(opts)
		done <- err
		return state, err
	}
	s.refreshOpenClawInstallPolicy()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("retry: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("the failed refresh was not retried (%d calls)", calls.Load())
	}
	if !openClawInstallPolicyStillRegistered(t, configPath) {
		t.Fatal("a retry under an unknown OpenClaw version removed the registered install policy (fail-open)")
	}
}

// Path b: a config reload changes an install policy input (the scan timeout)
// while the cache reads "": the reload refresh keeps the registered policy.
func TestOpenClawInstallPolicyReloadUnderAnUnknownVersionKeepsThePolicy(t *testing.T) {
	resetOpenClawInstallPolicyRetryState(t)
	s, dataDir, configPath := registeredOpenClawInstallPolicy(t, "2026.11.3")
	writeOpenClawDiscoveryVersion(t, dataDir, "")
	oldCfg := s.currentConfig()
	newCfg := *oldCfg
	newCfg.Scanners.SkillScanner.Timeouts.ScanS = 450
	if !openClawInstallPolicyReloadWanted(oldCfg, &newCfg) {
		t.Fatal("a new scan timeout must refresh the install policy")
	}
	s.cfgCurrent.Store(&newCfg)
	s.refreshOpenClawInstallPolicy()
	if !openClawInstallPolicyStillRegistered(t, configPath) {
		t.Fatal("a reload under an unknown OpenClaw version removed the registered install policy (fail-open)")
	}
}

// Path c: the watcher parses 2026.12.1, waits for the refresh lock, and the
// cache reads "" by the time the refresh runs. The refresh is judged under
// the version the watcher saw. (A known version goes on to the command check
// of this test binary, which is not what this test is about, so the stub
// answers for it; an unknown one goes to the real connector.)
func TestOpenClawInstallPolicyWatchRaceWithAnEmptyCacheKeepsThePolicy(t *testing.T) {
	resetOpenClawInstallPolicyRetryState(t)
	s, dataDir, configPath := registeredOpenClawInstallPolicy(t, "2026.11.3")
	real := openClawInstallPolicyRefresher
	seen := make(chan string, 8)
	openClawInstallPolicyRefresher = func(opts connector.SetupOpts) (string, error) {
		seen <- opts.AgentVersion
		if connector.NormalizeAgentVersion("openclaw", opts.AgentVersion) == "" {
			return real(opts)
		}
		return "registered", nil
	}
	openClawInstallPolicyVersionPoll = 5 * time.Millisecond
	stop := s.startOpenClawInstallPolicyWatch(context.Background())
	defer stop()

	openClawInstallPolicyRefreshMu.Lock()
	writeOpenClawDiscoveryVersion(t, dataDir, "2026.12.1")
	time.Sleep(200 * time.Millisecond) // the watcher parsed it and waits for the lock
	writeOpenClawDiscoveryVersion(t, dataDir, "")
	openClawInstallPolicyRefreshMu.Unlock()
	select {
	case got := <-seen:
		if got != "2026.12.1" {
			t.Errorf("the watcher's refresh was judged under OpenClaw %q, want the 2026.12.1 it saw", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the version change did not refresh the install policy")
	}
	stop()
	if !openClawInstallPolicyStillRegistered(t, configPath) {
		t.Fatal("the watcher race removed the registered install policy (fail-open)")
	}
}

// GAP-1198 review (P3) with the real connector: OpenClaw is downgraded below
// 2026.8.35 and the first refresh fails with no retry left (here none is
// configured; in the field all five failed). The watcher compares the cached
// version with the one the policy was written under, so it refreshes again
// and the policy OpenClaw cannot run is removed (fail closed). Before, it
// had already moved to the new version and never looked again.
func TestOpenClawInstallPolicyWatchRemovesAfterAFailedDowngradeRefresh(t *testing.T) {
	resetOpenClawInstallPolicyRetryState(t)
	s, dataDir, configPath := registeredOpenClawInstallPolicy(t, "2026.11.3")
	real := openClawInstallPolicyRefresher
	var calls atomic.Int32
	openClawInstallPolicyRetryDelays = nil
	openClawInstallPolicyRefresher = func(opts connector.SetupOpts) (string, error) {
		if calls.Add(1) == 1 {
			return "", errors.New("lock_busy")
		}
		return real(opts)
	}
	openClawInstallPolicyVersionPoll = 5 * time.Millisecond
	stop := s.startOpenClawInstallPolicyWatch(context.Background())
	defer stop()
	writeOpenClawDiscoveryVersion(t, dataDir, "2026.8.34")
	deadline := time.Now().Add(5 * time.Second)
	for openClawInstallPolicyStillRegistered(t, configPath) && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if openClawInstallPolicyStillRegistered(t, configPath) {
		t.Fatalf("the install policy stays registered under OpenClaw 2026.8.34 after a failed refresh (%d refreshes)", calls.Load())
	}
}

// GAP-1198 review (P3): a failed refresh is retried by the watcher while the
// cached version differs from the one the policy was written under, and only
// until one succeeds.
func TestOpenClawInstallPolicyWatchRetriesAFailedRefresh(t *testing.T) {
	resetOpenClawInstallPolicyRetryState(t)
	dir := t.TempDir()
	writeOpenClawDiscoveryVersion(t, dir, "2026.11.3")
	var calls, ok atomic.Int32
	openClawInstallPolicyRetryDelays = nil
	openClawInstallPolicyRefresher = func(opts connector.SetupOpts) (string, error) {
		if opts.AgentVersion != "2026.8.35" {
			t.Errorf("refreshed under %q, want 2026.8.35", opts.AgentVersion)
		}
		if calls.Add(1) <= 2 {
			return "", errors.New("lock_busy")
		}
		ok.Add(1)
		return "not registered: too old", nil
	}
	openClawInstallPolicyVersionPoll = 5 * time.Millisecond
	s := &Sidecar{}
	s.cfgCurrent.Store(openClawInstallPolicyTestConfig(t, dir, "on"))
	stop := s.startOpenClawInstallPolicyWatch(context.Background())
	defer stop()
	writeOpenClawDiscoveryVersion(t, dir, "2026.8.35")
	deadline := time.Now().Add(5 * time.Second)
	for ok.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if ok.Load() == 0 {
		t.Fatalf("the watcher did not retry a failed refresh while OpenClaw is still 2026.8.35 (%d refreshes)", calls.Load())
	}
	time.Sleep(80 * time.Millisecond)
	if calls.Load() != 3 {
		t.Fatalf("the watcher refreshed %d times, want 3 (two failures, then one that ran)", calls.Load())
	}
}
