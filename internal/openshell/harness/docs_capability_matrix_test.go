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

package harness

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// TestDocsCapabilityMatrixSandboxColumn keeps the docs capability matrix's
// OpenShell sandbox column a checked projection of the harness registry: a
// harness row shows its artifacts' tamper tier, a hook config file the
// artifacts really contain (root-owned for the managed tier), and the default
// image pin; every other row is pending. internal/gateway/connector checks the status against the
// SandboxArtifactProvider implementations.
func TestDocsCapabilityMatrixSandboxColumn(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("OpenShell sandbox artifacts are not rendered on Windows hosts")
	}
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve test source path")
	}
	path := filepath.Join(filepath.Dir(filename), "..", "..", "..", "docs-site", "data", "capability-matrix.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var documented struct {
		Connectors []struct {
			ID      string `json:"id"`
			Sandbox struct {
				Status     string `json:"status"`
				TamperTier string `json:"tamperTier"`
				HookConfig string `json:"hookConfig"`
				HarnessPin string `json:"harnessPin"`
			} `json:"sandbox"`
		} `json:"connectors"`
	}
	if err := json.Unmarshal(raw, &documented); err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}

	seen := map[string]bool{}
	for _, row := range documented.Connectors {
		sb := row.Sandbox
		spec, ok := Get(row.ID)
		if !ok {
			if sb.Status != "pending" || sb.TamperTier != "" || sb.HookConfig != "" || sb.HarnessPin != "" {
				t.Errorf("%s has no sandbox harness but documents sandbox %+v; want only status pending", row.ID, sb)
			}
			continue
		}
		seen[row.ID] = true
		artifacts := artifactsFor(t, spec)
		if sb.Status != "artifacts" {
			t.Errorf("%s sandbox.status=%q want artifacts", row.ID, sb.Status)
		}
		if sb.TamperTier != artifacts.TamperTier {
			t.Errorf("%s sandbox.tamperTier=%q want %q", row.ID, sb.TamperTier, artifacts.TamperTier)
		}
		if sb.HarnessPin != spec.DefaultVersion {
			t.Errorf("%s sandbox.harnessPin=%q want %q", row.ID, sb.HarnessPin, spec.DefaultVersion)
		}
		// A managed registration is a root-owned file; a user-tier one is
		// the file in the image HOME the harness reads.
		found := false
		for _, file := range artifacts.Files {
			if file.Path == sb.HookConfig && (file.Owner == connector.SandboxOwnerRoot || artifacts.TamperTier == connector.SandboxTamperTierUser) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("%s sandbox.hookConfig=%q is not a hook config file of its %s-tier sandbox artifacts", row.ID, sb.HookConfig, artifacts.TamperTier)
		}
	}
	for _, name := range Names() {
		if !seen[name] {
			t.Errorf("harness %s is missing from the docs capability matrix", name)
		}
	}
}
