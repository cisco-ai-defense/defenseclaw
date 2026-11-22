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

package connector

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func openClawInstallPolicySavedBinaryPath(t *testing.T, dataDir string) string {
	t.Helper()
	data, err := os.ReadFile(openClawInstallPolicyStatePath(dataDir))
	if err != nil {
		t.Fatal(err)
	}
	var rec map[string]any
	if err := json.Unmarshal(data, &rec); err != nil {
		t.Fatal(err)
	}
	path, _ := rec["openclaw_binary_path"].(string)
	return path
}

// GAP-1237: the install policy state records the openclaw executable the
// version was read from, so the gateway acts only on a cache from that
// executable. Setup is given it with the version; a refresh with no version
// of its own takes both from the discovery cache.
func TestOpenClawInstallPolicyStateRecordsTheOpenClawExecutable(t *testing.T) {
	configPath, _, opts := unknownVersionFixture(t)
	exe := filepath.Join(t.TempDir(), "openclaw")
	opts.AgentExecutable = exe
	if state := setupOpenClawInstallPolicy(t, configPath, opts); state != openClawInstallPolicyRegistered {
		t.Fatalf("setup: %q", state)
	}
	if got := openClawInstallPolicySavedBinaryPath(t, opts.DataDir); got != exe {
		t.Fatalf("state records openclaw executable %q, want %s", got, exe)
	}

	cached := filepath.Join(t.TempDir(), "openclaw")
	body, err := json.Marshal(map[string]any{"agents": map[string]any{
		"openclaw": map[string]any{"installed": true, "version": "2026.8.34", "binary_path": cached},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(opts.DataDir, "agent_discovery.json"), body, 0o600); err != nil {
		t.Fatal(err)
	}
	fromCache := opts
	fromCache.AgentVersion, fromCache.AgentExecutable = "", ""
	if _, err := NewOpenClawConnector().RefreshInstallPolicy(fromCache); err != nil {
		t.Fatal(err)
	}
	if _, version := openClawInstallPolicySavedState(t, opts.DataDir); version != "2026.8.34" {
		t.Fatalf("state saved under %q, want the cached 2026.8.34", version)
	}
	if got := openClawInstallPolicySavedBinaryPath(t, opts.DataDir); got != cached {
		t.Fatalf("state records openclaw executable %q, want the cached %s", got, cached)
	}
}
