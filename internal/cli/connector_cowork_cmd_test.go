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

//go:build !windows

package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// TestConnectorCoworkPluginExitCodesAndReasons pins what setup cowork reads:
// exit 2 without a data dir; exit 1 with reason claudecode_not_set_up, then
// managed; exit 0 with the hooks document.
func TestConnectorCoworkPluginExitCodesAndReasons(t *testing.T) {
	savedCfg, savedDir, savedJSON, savedExit := cfg, connectorFlagDataDir, connectorFlagJSON, connectorExit
	t.Cleanup(func() {
		cfg, connectorFlagDataDir, connectorFlagJSON, connectorExit = savedCfg, savedDir, savedJSON, savedExit
	})

	run := func() (int, map[string]any) {
		t.Helper()
		var out, errOut bytes.Buffer
		cmd := &cobra.Command{Use: "cowork-plugin"}
		cmd.SetOut(&out)
		cmd.SetErr(&errOut)
		code := 0
		connectorExit = func(exit int) { code = exit }
		if err := runConnectorCoworkPlugin(cmd, nil); err != nil {
			t.Fatal(err)
		}
		var doc map[string]any
		if out.Len() > 0 {
			if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
				t.Fatalf("stdout %q: %v", out.String(), err)
			}
		}
		return code, doc
	}

	cfg, connectorFlagDataDir, connectorFlagJSON = nil, "", true
	if code, _ := run(); code != 2 {
		t.Fatalf("no data dir: exit %d, want 2", code)
	}

	dataDir := t.TempDir()
	connectorFlagDataDir = dataDir
	cfg = &config.Config{DataDir: dataDir}
	if code, doc := run(); code != 1 || doc["reason"] != "claudecode_not_set_up" {
		t.Fatalf("not set up: exit %d doc %v", code, doc)
	}

	if err := connector.SaveHookContractLockEntry(dataDir, connector.HookContractLockEntry{Connector: "claudecode", ContractID: "claudecode-test"}); err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(dataDir, "hooks", "claude-code-hook.sh")
	if err := os.MkdirAll(filepath.Dir(script), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(script, []byte("#!/bin/bash\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	cfg = &config.Config{DataDir: dataDir, DeploymentMode: managed.DeploymentModeManagedEnterprise}
	if code, doc := run(); code != 1 || doc["reason"] != "managed" {
		t.Fatalf("managed: exit %d doc %v", code, doc)
	}

	cfg = &config.Config{DataDir: dataDir}
	code, doc := run()
	hooks, _ := doc["hooks"].(map[string]any)
	if code != 0 || len(hooks) != len(connector.CoworkPluginHookEvents) {
		t.Fatalf("set up: exit %d, %d events (doc %v)", code, len(hooks), doc)
	}
}
