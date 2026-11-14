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

// TestGAP0307SubstrateFileReloadRefusesADeploymentModeEditWhole: on a
// Substrate pod the gateway's own file reload refuses an edit that changes
// deployment_mode, as the Substrate config watch does, instead of applying
// its guardrail part.
func TestGAP0307SubstrateFileReloadRefusesADeploymentModeEditWhole(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, config.DefaultConfigName)
	writeConfigForManagerTest(t, path, dir, "observe")
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
	runtime, _ := newProxyGeneratedTraceRuntime(t)
	mgr.bindObservabilityV8(runtime)
	raw := "config_version: 8\n" +
		"data_dir: " + dir + "\n" +
		"deployment_mode: managed_enterprise\n" +
		"guardrail:\n" +
		"  mode: action\n" +
		"substrate:\n" +
		"  enabled: true\n" +
		"observability: {}\n"
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	err = mgr.Reload(context.Background(), "test")
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
