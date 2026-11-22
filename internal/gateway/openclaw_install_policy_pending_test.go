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
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// GAP-1236: a reload changes an install policy input (the scan timeout)
// while the cache reads "": the real connector keeps the registered policy
// as it is ("not changed: OpenClaw version unknown"), so the change is still
// owed. When the cache returns to the version the policy was written under,
// the watcher runs the owed refresh with the new input. Before, the unknown
// result cleared the owed flag and the watcher compared versions only, so
// the change stayed unapplied until a restart or another reload.
func TestOpenClawInstallPolicyChangeMadeUnderAnUnknownVersionIsAppliedLater(t *testing.T) {
	resetOpenClawInstallPolicyRetryState(t)
	s, dataDir, configPath := registeredOpenClawInstallPolicy(t, "2026.11.3")
	real := openClawInstallPolicyRefresher
	applied := make(chan connector.SetupOpts, 8)
	openClawInstallPolicyRefresher = func(opts connector.SetupOpts) (string, error) {
		if connector.NormalizeAgentVersion("openclaw", opts.AgentVersion) == "" {
			return real(opts)
		}
		// A known version goes on to the command check of this test binary,
		// which is not what this test is about.
		applied <- opts
		return "registered", nil
	}
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
		t.Fatal("a reload under an unknown OpenClaw version removed the registered install policy")
	}
	if !openClawInstallPolicyPending.Load() {
		t.Fatal("a refresh that kept the policy under an unknown version cleared the owed refresh: the new scan timeout is lost")
	}

	openClawInstallPolicyVersionPoll = 2 * time.Millisecond
	stop := s.startOpenClawInstallPolicyWatch(context.Background())
	defer stop()
	writeOpenClawDiscoveryVersion(t, dataDir, "2026.11.3")
	select {
	case opts := <-applied:
		if opts.AgentVersion != "2026.11.3" {
			t.Errorf("the owed refresh judged under %q, want 2026.11.3", opts.AgentVersion)
		}
		if want := newCfg.OpenClawInstallPolicyTimeoutMs(); opts.OpenClawInstallPolicyTimeoutMs != want {
			t.Errorf("the owed refresh wrote timeout %d ms, want the reloaded %d ms", opts.OpenClawInstallPolicyTimeoutMs, want)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the cache returned to 2026.11.3 and the owed refresh never ran")
	}
	deadline := time.Now().Add(5 * time.Second)
	for openClawInstallPolicyPending.Load() && time.Now().Before(deadline) {
		time.Sleep(2 * time.Millisecond)
	}
	if openClawInstallPolicyPending.Load() {
		t.Fatal("the refresh that ran did not clear the owed flag")
	}
}
