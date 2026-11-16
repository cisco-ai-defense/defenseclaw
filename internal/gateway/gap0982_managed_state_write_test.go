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
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// TestClientWriteTargetNativeSpelling: on Windows a forward-slash spelling of
// a path finds the client's answer keyed by the native path; elsewhere only
// the spelling itself is a key (rel-1-0-10:GAP-0982).
func TestClientWriteTargetNativeSpelling(t *testing.T) {
	native := filepath.Join(t.TempDir(), ".defenseclaw", "config.yaml")
	if err := os.MkdirAll(filepath.Dir(native), 0o700); err != nil {
		t.Fatal(err)
	}
	targets := map[string]string{native: native}
	if got, ok := firstClientWriteTarget(targets, native); !ok || got != native {
		t.Fatalf("native spelling: %q, %v", got, ok)
	}
	got, ok := firstClientWriteTarget(targets, filepath.ToSlash(native))
	if runtime.GOOS == "windows" {
		if !ok || got != native {
			t.Fatalf("forward-slash spelling on Windows: %q, %v", got, ok)
		}
	} else if filepath.ToSlash(native) == native && (!ok || got != native) {
		t.Fatalf("POSIX spelling: %q, %v", got, ok)
	}
	if _, ok := firstClientWriteTarget(targets, ""); ok {
		t.Fatal("an empty spelling has no target")
	}
}

// TestGAP0982ManagedStateWriteIsNeverWeakerThanPerUser: a shell redirect or
// tee into DefenseClaw state is judged for a managed hook peer (whose
// gateway reads the write targets from the hook client's map) at least as
// strictly as by the per-user gateway, for a call the analysis reads in
// full or in part, on every operating system (rel-1-0-10:GAP-0982: on
// Windows the managed tiers allowed a call read in part).
func TestGAP0982ManagedStateWriteIsNeverWeakerThanPerUser(t *testing.T) {
	keepTempDirOffDevice(t)
	home := t.TempDir()
	cwd := filepath.Join(home, "project")
	state := filepath.Join(home, ".defenseclaw")
	for _, dir := range []string{state, cwd} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, file := range []string{filepath.Join(state, "config.yaml"), filepath.Join(cwd, "notes.txt")} {
		if err := os.WriteFile(file, []byte("marker\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	rank := map[string]int{"allow": 0, "alert": 1, "block": 2}
	targets := []string{"~/.defenseclaw/config.yaml", "$HOME/.defenseclaw/config.yaml"}
	forms := []string{
		"/opt/tools/add-key notes.txt > %s", "add-key notes.txt >> %s", "echo x > %s", "echo x >> %s",
		"echo x 2>&1 > %s", "echo x > %s 2>&1", "echo x | tee %s", "echo x | tee -a %s",
	}
	for _, posture := range []string{"default", "strict"} {
		installToolCallCorpusProfileConnector(t, "claudecode", posture)
		cfg := &config.Config{}
		cfg.Guardrail.Mode = "action"
		cfg.Guardrail.Connector = "claudecode"
		cfg.Guardrail.RulePackDir = filepath.Join(guardrailPoliciesRoot(t), posture)
		api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth()}
		rt := claudeCodeHookProfileRuntime(connector.HookProfile{Name: "claudecode"})
		for _, target := range targets {
			for _, form := range forms {
				command := fmt.Sprintf(form, target)
				for _, tool := range []string{"Bash", "PowerShell"} {
					body, _ := json.Marshal(map[string]any{"hook_event_name": "PreToolUse", "cwd": cwd,
						"tool_name": tool, "tool_input": map[string]any{"command": command}})
					decide := func(ctx context.Context) string {
						var payload map[string]interface{}
						_ = json.Unmarshal(body, &payload)
						return rt.Evaluate(api, ctx, agentHookRequest{ConnectorName: "claudecode", HookEventName: "PreToolUse"}, body, payload).Action
					}
					perUser := decide(context.Background())
					managed := withManagedHookPeer(context.Background(), managedHookPeer{Home: home})
					if resolved, ok := hookpaths.Decode(hookpaths.Resolve(body)); ok {
						managed = context.WithValue(managed, resolvedWritesContextKey{}, resolved)
					}
					if got := decide(managed); rank[got] < rank[perUser] {
						t.Errorf("%s %s %q: managed %s, per-user %s", posture, tool, command, got, perUser)
					}
				}
			}
		}
	}
}
