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
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// GAP-1170: only OpenClaw 2026.11.3 and later skip inherit-only ACEs; 8.35,
// any release between and an unknown version are held to the older rule.
func TestOpenClawSkipsInheritOnlyACEs(t *testing.T) {
	for v, want := range map[string]bool{
		"2026.11.3": true, "2026.11.5": true, "OpenClaw 2026.11.3 (847611d)": true, "2026.12.1": true,
		"2026.8.35": false, "OpenClaw 2026.8.35 (713ba57)": false, "2026.10.9": false, "": false, "garbage": false,
	} {
		if got := openClawSkipsInheritOnlyACEs(v); got != want {
			t.Errorf("openClawSkipsInheritOnlyACEs(%q) = %v, want %v", v, got, want)
		}
	}
}

// GAP-1170: the too-old refusal reaches the state unwrapped, and the state
// is kept for doctor and status; teardown removes the state file.
func TestOpenClawInstallPolicyTooOldStateIsSaved(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "openclaw.json")
	if err := os.WriteFile(configPath, []byte("{}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	command := filepath.Join(dir, "defenseclaw-gateway")
	if err := os.WriteFile(command, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	prevExe, prevTrust := openClawInstallPolicyExecutable, openClawInstallPolicyTrusted
	t.Cleanup(func() { openClawInstallPolicyExecutable, openClawInstallPolicyTrusted = prevExe, prevTrust })
	openClawInstallPolicyExecutable = func() (string, error) { return command, nil }
	var gotVersion string
	openClawInstallPolicyTrusted = func(_, _, version string) error {
		gotVersion = version
		return &openClawInstallPolicyTooOldError{version: "2026.8.35", cause: errors.New(`C:\ has the inherit-only entry CREATOR OWNER`)}
	}
	opts := SetupOpts{DataDir: dir, AgentVersion: "2026.8.35", OpenClawInstallPolicy: true}
	state, err := applyOpenClawInstallPolicy(configPath, opts)
	want := "not registered: OpenClaw 2026.8.35 is too old for strict install policy on Windows (needs 2026.11.3 or later)"
	if err != nil || !strings.HasPrefix(state, want) || gotVersion != "2026.8.35" {
		t.Fatalf("state = %q, err = %v, version passed = %q", state, err, gotVersion)
	}
	saved, err := os.ReadFile(openClawInstallPolicyStatePath(dir))
	if err != nil || !strings.Contains(string(saved), "is too old for strict install policy") {
		t.Fatalf("state file = %s (%v)", saved, err)
	}
	discardOpenClawInstallPolicyState(dir)
	if _, err := os.Stat(openClawInstallPolicyStatePath(dir)); !os.IsNotExist(err) {
		t.Fatalf("state file left: %v", err)
	}
}
