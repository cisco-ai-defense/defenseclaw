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

package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// rel-1-0-2:GAP-0483: the installer runs `defenseclaw-gateway sandbox
// carry-state` between a rollback's swap and the gateway start, with no
// gateway running and no config.yaml loaded for it (the sandbox commands'
// pre-run would load one and refuse while sandboxes are off). It prints
// the line the installer shows and keeps the running sandbox's binding.
func TestSandboxCarryStateRunsForTheInstallerWithoutTheSandboxPreRun(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HOME", root)
	left, live := filepath.Join(root, "previous", "data"), filepath.Join(root, ".defenseclaw")
	t.Setenv("DEFENSECLAW_HOME", live)
	for _, dir := range []string{filepath.Join(left, "sandboxes", "manager"), live} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	files := map[string]string{
		filepath.Join(left, "config.yaml"):                                "config_version: 9\ndata_dir: " + left + "\nopenshell:\n  enabled: true\n  harnesses: [codex]\n",
		filepath.Join(left, "sandboxes", "manager", "wv102-b-codex.json"): `{"version":1,"name":"wv102-b-codex"}`,
		filepath.Join(left, "sandboxes", "bindings.json"):                 `{"bindings":[{"id":"b-1.0.2"}]}`,
		filepath.Join(live, "config.yaml"):                                "config_version: 9\ndata_dir: " + live + "\n",
	}
	for path, body := range files {
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	var carry bool
	for _, cmd := range sandboxCmd.Commands() {
		if cmd.Name() == "carry-state" {
			carry = cmd.Hidden
		}
	}
	if !carry {
		t.Fatal("sandbox carry-state is missing or not hidden")
	}

	var stdout, stderr bytes.Buffer
	originalOut, originalErr := rootCmd.OutOrStdout(), rootCmd.ErrOrStderr()
	t.Cleanup(func() {
		rootCmd.SetArgs(nil)
		rootCmd.SetOut(originalOut)
		rootCmd.SetErr(originalErr)
	})
	rootCmd.SetOut(&stdout)
	rootCmd.SetErr(&stderr)
	rootCmd.SetArgs([]string{"sandbox", "carry-state",
		"--from-data", left, "--from-config", filepath.Join(left, "config.yaml"),
		"--data-dir", live, "--config", filepath.Join(live, "config.yaml")})
	if _, err := rootCmd.ExecuteC(); err != nil {
		t.Fatalf("carry-state: %v (stderr %q)", err, stderr.String())
	}
	if got := stdout.String(); !strings.Contains(got, "Kept the sandbox setup") || !strings.Contains(got, "sandbox wv102-b-codex") {
		t.Fatalf("stdout = %q", got)
	}
	raw, err := os.ReadFile(filepath.Join(live, "sandboxes", "bindings.json"))
	if err != nil || !strings.Contains(string(raw), "b-1.0.2") {
		t.Fatalf("binding not carried: %q, %v", raw, err)
	}
	raw, err = os.ReadFile(filepath.Join(live, "config.yaml"))
	if err != nil || !strings.Contains(string(raw), "enabled: true") {
		t.Fatalf("openshell settings not carried:\n%s (%v)", raw, err)
	}
}
