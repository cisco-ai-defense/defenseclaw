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
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// gap0307Reload starts an OSS Substrate gateway manager on config.yaml in
// guardrail observe mode, writes an edit that adds deployment_mode
// managed_enterprise and turns the guardrail to action, and reloads it.
// trusted loads the candidate as on a path the managed trust check accepts,
// from a managed config the loader takes.
func gap0307Reload(t *testing.T, trusted bool) (*ConfigManager, bool, error) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, config.DefaultConfigName)
	boot := "config_version: 9\ndata_dir: " + dir + "\nguardrail:\n  mode: observe\nobservability: {}\n"
	if err := os.WriteFile(path, []byte(boot), 0o600); err != nil {
		t.Fatal(err)
	}
	initial, err := config.LoadRuntimeV8File(path)
	if err != nil {
		t.Fatalf("initial load: %v", err)
	}
	initial.Substrate.Enabled = true
	applied := false
	mgr := newConfigManagerWithSnapshot(path, initial, nil, nil, "", func(context.Context, *config.Config, *config.Config, ConfigDiff, configReloadSource) error {
		applied = true
		return nil
	})
	if trusted {
		// The loader as on a trusted managed path with a complete managed
		// config: the edit decodes, and the candidate runs as managed.
		mgr.loadSnapshot = func(source string, raw []byte) (*config.Config, error) {
			oss := strings.Replace(string(raw), "deployment_mode: managed_enterprise\n", "", 1)
			c, err := config.LoadRuntimeV8InspectionCandidateFromBytes(source, []byte(oss))
			if err == nil {
				c.DeploymentMode = "managed_enterprise"
			}
			return c, err
		}
	}
	runtime, _ := newProxyGeneratedTraceRuntime(t)
	mgr.bindObservabilityV8(runtime)
	raw := "config_version: 9\n" +
		"data_dir: " + dir + "\n" +
		"deployment_mode: managed_enterprise\n" +
		"guardrail:\n" +
		"  mode: action\n" +
		"substrate:\n" +
		"  enabled: true\n" +
		"  identity:\n" +
		"    issuer: https://idp.ate-system.svc\n" +
		"    audience: defenseclaw\n" +
		"    token_lifetime_seconds: 300\n" +
		"observability: {}\n"
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	return mgr, applied, mgr.Reload(context.Background(), "test")
}

// TestGAP0307SubstrateFileReloadRefusesADeploymentModeEditWhole: on a
// Substrate pod the gateway's own file reload refuses an edit that changes
// deployment_mode, as the Substrate config watch does, instead of applying
// its guardrail part.
func TestGAP0307SubstrateFileReloadRefusesADeploymentModeEditWhole(t *testing.T) {
	mgr, applied, err := gap0307Reload(t, false)
	if err == nil || applied {
		t.Fatalf("a deployment_mode edit was applied on a Substrate pod (err %v, applied %v)", err, applied)
	}
	if got := mgr.Current().Guardrail.Mode; got != "observe" {
		t.Fatalf("guardrail mode %q applied from a refused edit", got)
	}
	t.Logf("refusal: %v", err)
	if !strings.Contains(err.Error(), "deployment_mode") && !strings.Contains(err.Error(), "managed") {
		t.Fatalf("refusal does not name deployment_mode: %v", err)
	}
}

// TestGAP0307TrustedFileReloadRefusesADeploymentModeEditWhole is the same
// edit on a config path the managed trust check accepts (the test file is
// not root-owned, so the loader's trust check refused the edit above before
// the deployment_mode check was reached): the guardrail part must not apply.
func TestGAP0307TrustedFileReloadRefusesADeploymentModeEditWhole(t *testing.T) {
	mgr, applied, err := gap0307Reload(t, true)
	if err == nil || applied {
		t.Fatalf("a deployment_mode edit was applied on a Substrate pod (err %v, applied %v)", err, applied)
	}
	if got := mgr.Current().Guardrail.Mode; got != "observe" {
		t.Fatalf("guardrail mode %q applied from a refused edit", got)
	}
	if !strings.Contains(err.Error(), "deployment_mode") {
		t.Fatalf("refusal does not name deployment_mode: %v", err)
	}
}

// TestGAP0323SubstrateFileReloadNamesTheModeChange: the refusal names the
// deployment_mode change, not the managed trust check of the mounted file.
func TestGAP0323SubstrateFileReloadNamesTheModeChange(t *testing.T) {
	_, _, err := gap0307Reload(t, false)
	if err == nil {
		t.Fatal("a deployment_mode edit was not refused")
	}
	if msg := err.Error(); !strings.Contains(msg, "deployment_mode_change") || strings.Contains(msg, "trust check") {
		t.Fatalf("refusal does not name the deployment_mode change: %v", msg)
	}
}
