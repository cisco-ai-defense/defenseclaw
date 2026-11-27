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
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
)

// TestGAP2057PrivateKeyFileToolWriteKeepsTheShellWriteCell pins the Claude
// Code Write and Edit tools to the cell of the shell write to the same
// ~/.ssh private-key name (echo k > ~/.ssh/id_ed25519) in the five tiers:
// the same action and severity, the PATH-SSH-DIR finding on both (rel-1-0-10
// GAP-2057: the live Write of ~/.ssh/id_ed25519 alerted HIGH and ran, as the
// shell write does in the default tier). A project file named like a key
// (id_ed25519.pub.example) stays allowed.
func TestGAP2057PrivateKeyFileToolWriteKeepsTheShellWriteCell(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX home spellings")
	}
	home := t.TempDir()
	proj := filepath.Join(home, "proj")
	for _, dir := range []string{".ssh", "proj/keys"} {
		if err := os.MkdirAll(filepath.Join(home, dir), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(home, ".ssh/id_ed25519"), []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	decide := func(api *APIServer, tool string, input map[string]interface{}) (string, string, []string) {
		resp := api.evaluateClaudeCodeHook(t.Context(), claudeCodeHookRequest{
			HookEventName: "PreToolUse", SessionID: "gap2057", CWD: proj, ToolName: tool, ToolInput: input,
		})
		return resp.Action, resp.Severity, resp.Findings
	}
	for _, tier := range boundedTestTiers {
		api := gap0589TierAPI(t, "claudecode", tier.posture, tier.managed, tier.tier)
		useDefaultEffectsLane(t)
		for _, name := range actionPrivateKeyNamesForTest() {
			rel := ".ssh/" + name
			abs := filepath.Join(home, rel)
			shellAction, shellSeverity, shellFindings := decide(api, "Bash", map[string]interface{}{"command": "echo k > ~/" + rel})
			if shellAction == "allow" || !gap0589HasRule(shellFindings, "PATH-SSH-DIR") {
				t.Fatalf("%s shell write of ~/%s: %s %v, want PATH-SSH-DIR", tier.name, rel, shellAction, shellFindings)
			}
			// The documented cell (protected-files.mdx, Limits): a HIGH
			// alert, a block only in the strict tiers (owner tiering of the
			// SSH key family; block-in-default stays an owner question).
			want := gap2057DocumentedAction(tier.tier)
			if shellAction != want || shellSeverity != "HIGH" && want == "alert" {
				t.Errorf("%s shell write of ~/%s: %s %s, want the documented %s", tier.name, rel, shellAction, shellSeverity, want)
			}
			for _, verb := range []string{"mv", "ln -sf"} {
				command := verb + " " + filepath.Join(proj, "k") + " ~/" + rel
				action, severity, findings := decide(api, "Bash", map[string]interface{}{"command": command})
				if action != want || severity != "HIGH" && want == "alert" {
					t.Errorf("%s %s onto ~/%s: %s %s %v, want the documented %s", tier.name, verb, rel, action, severity, findings, want)
				}
			}
			for tool, input := range map[string]map[string]interface{}{
				"Write": {"file_path": abs, "content": "k\n"},
				"Edit":  {"file_path": abs, "old_string": "x", "new_string": "k"},
			} {
				action, severity, findings := decide(api, tool, input)
				if action != shellAction || severity != shellSeverity || !gap0589HasRule(findings, "PATH-SSH-DIR") {
					t.Errorf("%s %s ~/%s: %s %s %v, want the shell write's %s %s with PATH-SSH-DIR",
						tier.name, tool, rel, action, severity, findings, shellAction, shellSeverity)
				}
			}
		}
		example := filepath.Join(proj, "keys/id_ed25519.pub.example")
		if action, _, findings := decide(api, "Write", map[string]interface{}{"file_path": example, "content": "k\n"}); action != "allow" {
			t.Errorf("%s Write of a project id_ed25519.pub.example: %s %v, want allow", tier.name, action, findings)
		}
	}
}

// gap2057DocumentedAction is the action the protected-files page gives a
// write to a private-key name: block in the strict tiers, else alert.
func gap2057DocumentedAction(tier bounded.Tier) string {
	if tier == bounded.TierStrict {
		return "block"
	}
	return "alert"
}

// TestGAP2057ProtectedFilesDocsNamePrivateKeyWrites: the protected-files
// page says what a write to a private-key name in .ssh gets, the cell
// TestGAP2057PrivateKeyFileToolWriteKeepsTheShellWriteCell pins: the watch
// does not cover these files, the hook raises a HIGH alert and blocks only
// in the strict packs (rel-1-0-10:GAP-2057: the docs listed only
// authorized_keys for .ssh and said nothing of these names).
func TestGAP2057ProtectedFilesDocsNamePrivateKeyWrites(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "docs-site", "content", "docs", "guardrail", "protected-files.mdx"))
	if err != nil {
		t.Fatal(err)
	}
	_, limits, ok := strings.Cut(string(data), "\n## Limits\n")
	if !ok {
		t.Fatal("protected-files.mdx has no Limits section")
	}
	var line string
	for _, item := range strings.Split(limits, "\n- ") {
		if strings.Contains(item, "private-key") {
			line = strings.Join(strings.Fields(item), " ")
		}
	}
	if line == "" {
		t.Fatal("protected-files.mdx Limits names no private-key write")
	}
	for _, want := range append(actionPrivateKeyNamesForTest(), ".pub", "HIGH alert", "strict", "ssh-keygen") {
		if !strings.Contains(line, want) {
			t.Errorf("protected-files.mdx private-key limit does not say %q: %s", want, line)
		}
	}
}

// actionPrivateKeyNamesForTest is the private-key names the read guard
// reads (hookpaths actionPrivateKeyNames).
func actionPrivateKeyNamesForTest() []string {
	return []string{"id_rsa", "id_ed25519", "id_ecdsa", "id_dsa"}
}
