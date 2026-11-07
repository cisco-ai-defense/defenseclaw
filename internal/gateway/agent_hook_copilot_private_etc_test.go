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

package gateway

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

func TestSystemEtcPathNamesTheMacOSPhysicalTarget(t *testing.T) {
	for value, want := range map[string]string{
		"/private/etc/shadow": "/etc/shadow",
		"/private/etc":        "/etc",
		"/etc/shadow":         "/etc/shadow",
		"/private/etcetera":   "/private/etcetera",
		"/private/var/x":      "/private/var/x",
		"/home/u/private/etc": "/home/u/private/etc",
	} {
		if got := systemEtcPath(value); got != want {
			t.Errorf("systemEtcPath(%q) = %q, want %q", value, got, want)
		}
	}
}

// On macOS /etc is a link to /private/etc, so the hook resolves a project link
// to /etc/shadow, present or not, as /private/etc/shadow. The call must be
// judged like the direct name in every non-strict profile, on any OS: the
// evidence below carries the macOS spelling (GAP-0769).
func TestGAP0769LinkResolvedThroughMacOSPrivateEtcIsProtected(t *testing.T) {
	installSandboxMarkerRules(t)
	store, logger := testStoreAndLogger(t)
	project := t.TempDir()
	ordinary := filepath.Join(project, "notes.txt")
	if err := os.WriteFile(ordinary, []byte("notes"), 0o600); err != nil {
		t.Fatal(err)
	}
	linked := filepath.Join(project, "linked.txt")
	if err := os.Symlink("/etc/shadow", linked); err != nil {
		t.Fatal(err)
	}
	hostsLinked := filepath.Join(project, "hosts-linked.txt")
	if err := os.Symlink("/etc/hosts", hostsLinked); err != nil {
		t.Fatal(err)
	}
	calls := []struct {
		name, tool string
		input      map[string]any
		protected  bool
	}{
		{"create", "create_file", map[string]any{"filePath": linked, "content": "x"}, true},
		{"write_file", "write_file", map[string]any{"path": linked, "content": "x"}, true},
		{"append_file", "append_file", map[string]any{"path": linked, "content": "x"}, true},
		{"ordinary read", "read_file", map[string]any{"filePath": ordinary}, false},
		{"hosts read", "read_file", map[string]any{"filePath": hostsLinked}, false},
		{"hosts write", "write_file", map[string]any{"path": hostsLinked, "content": "x"}, false},
	}
	macOS := map[string]string{
		"/etc/shadow": "/private/etc/shadow",
		"/etc/hosts":  "/private/etc/hosts",
	}
	for _, tier := range []string{"implicit", "default", "permissive"} {
		t.Run(tier, func(t *testing.T) {
			cfg := &config.Config{}
			cfg.Guardrail.Mode = "action"
			cfg.Guardrail.Connector = "copilot"
			if tier != "implicit" {
				cfg.Guardrail.RulePack = tier
			}
			api := &APIServer{scannerCfg: cfg, store: store, logger: logger}
			for index, tc := range calls {
				t.Run(tc.name, func(t *testing.T) {
					id := "gap0769-" + tier + "-" + strconv.Itoa(index)
					raw, err := json.Marshal(map[string]any{
						"hook_event_name": "PreToolUse", "session_id": id,
						"tool_use_id": id, "cwd": project,
						"tool_name": tc.tool, "tool_input": tc.input,
					})
					if err != nil {
						t.Fatal(err)
					}
					targets, ok := hookpaths.Decode(hookpaths.ResolveConnector("copilot", "", "preToolUse", raw))
					if !ok {
						t.Fatal("hook evidence did not decode")
					}
					rewritten := 0
					for key, value := range targets {
						if physical, found := macOS[value]; found {
							targets[key] = physical
							rewritten++
						}
					}
					if tc.protected && rewritten == 0 {
						t.Fatalf("no resolved target to spell the macOS way: %v", targets)
					}
					req := httptest.NewRequest(http.MethodPost, "/api/v1/copilot/hook", strings.NewReader(string(raw)))
					req.Header.Set("Content-Type", "application/json")
					req.Header.Set("X-DefenseClaw-Copilot-Event", "preToolUse")
					req.Header.Set(hookpaths.Header, encodeTargets(t, targets))
					w := httptest.NewRecorder()
					api.handleAgentHook("copilot").ServeHTTP(w, req)
					var answer struct {
						Action  string   `json:"action"`
						RuleIDs []string `json:"rule_ids"`
					}
					if err := json.Unmarshal(w.Body.Bytes(), &answer); err != nil || w.Code != http.StatusOK {
						t.Fatalf("status=%d err=%v body=%s", w.Code, err, w.Body.String())
					}
					want := "allow"
					if tc.protected {
						want = "block"
					}
					if answer.Action != want {
						t.Fatalf("action=%s, want %s; rules=%v", answer.Action, want, answer.RuleIDs)
					}
					if tc.protected && !slices.ContainsFunc(answer.RuleIDs, func(id string) bool {
						return id == "PATH-ETC-SHADOW"
					}) {
						t.Fatalf("protected file rule absent: %v", answer.RuleIDs)
					}
				})
			}
		})
	}
}

// The same physical spelling reaches every exact /etc rule, not only the
// shadow and passwd file rules, and a shell write follows a link like a file
// tool does: a shell write through a project link to the loader preload file
// or the system profile is judged like the direct name in every non-strict
// profile, whether the link target is spelled /etc or /private/etc
// (GAP-0769 review round 6).
func TestGAP0769ShellWriteLinkedToExactEtcRuleIsProtected(t *testing.T) {
	installSandboxMarkerRules(t)
	store, logger := testStoreAndLogger(t)
	project := t.TempDir()
	const preload = "echo /usr/local/lib/libguard.so > %s"
	cases := []struct {
		name, link, target, command, rule string
		// physical spells the resolved target the macOS way.
		physical bool
		// blocks is the action the rule takes; an alert-only rule allows.
		blocks bool
	}{
		{"direct loader preload", "", "/etc/ld.so.preload", preload, "persistence.global_ld_preload_install", false, true},
		{"linked loader preload", "preload.txt", "/etc/ld.so.preload", preload, "persistence.global_ld_preload_install", false, true},
		{"macOS linked loader preload", "preload-mac.txt", "/etc/ld.so.preload", preload, "persistence.global_ld_preload_install", true, true},
		{"direct system profile", "", "/etc/profile", "echo export GUARD=1 >> %s", "persistence.shell_profile_write", false, false},
		{"macOS linked system profile", "profile-mac.txt", "/etc/profile", "echo export GUARD=1 >> %s", "persistence.shell_profile_write", true, false},
		{"macOS linked hosts twin", "hosts-mac.txt", "/etc/hosts", "echo 127.0.0.1 guard >> %s", "", true, false},
		{"ordinary twin", "", "", "echo notes > %s", "", false, false},
		// A write that opens the link reaches the system file; a command that
		// replaces the link entry leaves it alone (GAP-0769 review round 7).
		{"copy through a link", "shadow-cp.txt", "/etc/shadow", "cp /etc/hosts %s", "PATH-ETC-SHADOW", false, true},
		{"redirect through a link", "shadow-redirect.txt", "/etc/shadow", "echo x > %s", "PATH-ETC-SHADOW", false, true},
		{"macOS copy through a link", "shadow-mac.txt", "/etc/shadow", "cp /etc/hosts %s", "PATH-ETC-SHADOW", true, true},
		{"direct ln onto the file", "", "/etc/shadow", "ln -sf /etc/hosts %s", "PATH-ETC-SHADOW", false, true},
		{"direct remove-destination copy", "", "/etc/shadow", "cp --remove-destination /etc/hosts %s", "PATH-ETC-SHADOW", false, true},
		{"ln through a linked directory", "etc-dir-ln", "/etc", "ln -sf /etc/hosts %s/shadow", "PATH-ETC-SHADOW", false, true},
		{"remove-destination copy through a linked directory", "etc-dir-cp", "/etc", "cp --remove-destination /etc/hosts %s/shadow", "PATH-ETC-SHADOW", false, true},
		{"ln replaces the link", "ln-replace.txt", "/etc/shadow", "ln -sf /etc/hosts %s", "", false, false},
		{"remove-destination copy replaces the link", "cp-replace.txt", "/etc/shadow", "cp --remove-destination /etc/hosts %s", "", false, false},
		{"abbreviated remove-destination replaces the link", "cp-rem.txt", "/etc/shadow", "cp --rem /etc/hosts %s", "", false, false},
		{"install replaces the link", "install-replace.txt", "/etc/shadow", "install -m 644 /etc/hosts %s", "", false, false},
		{"move replaces the link", "mv-replace.txt", "/etc/shadow", "mv notes.txt %s", "", false, false},
		{"macOS ln replaces the link", "ln-replace-mac.txt", "/etc/shadow", "ln -sf /etc/hosts %s", "", true, false},
	}
	for _, tier := range []string{"implicit", "default", "permissive"} {
		t.Run(tier, func(t *testing.T) {
			cfg := &config.Config{}
			cfg.Guardrail.Mode = "action"
			cfg.Guardrail.Connector = "copilot"
			if tier != "implicit" {
				cfg.Guardrail.RulePack = tier
			}
			api := &APIServer{scannerCfg: cfg, store: store, logger: logger}
			for index, tc := range cases {
				t.Run(tc.name, func(t *testing.T) {
					file := filepath.Join(project, "ordinary.txt")
					switch {
					case tc.link != "":
						file = filepath.Join(project, tier+"-"+tc.link)
						if err := os.Symlink(tc.target, file); err != nil {
							t.Fatal(err)
						}
					case tc.target != "":
						file = tc.target
					}
					id := "gap0769-shell-" + tier + "-" + strconv.Itoa(index)
					raw, err := json.Marshal(map[string]any{
						"hook_event_name": "PreToolUse", "session_id": id,
						"tool_use_id": id, "cwd": project,
						"tool_name":  "run_in_terminal",
						"tool_input": map[string]any{"command": strings.Replace(tc.command, "%s", file, 1), "explanation": "x", "isBackground": false},
					})
					if err != nil {
						t.Fatal(err)
					}
					targets, ok := hookpaths.Decode(hookpaths.ResolveConnector("copilot", "", "preToolUse", raw))
					if !ok {
						t.Fatal("hook evidence did not decode")
					}
					if tc.physical {
						rewritten := 0
						for key, value := range targets {
							if value == tc.target {
								targets[key] = "/private" + tc.target
								rewritten++
							}
						}
						if rewritten == 0 {
							t.Fatalf("no resolved target to spell the macOS way: %v", targets)
						}
					}
					req := httptest.NewRequest(http.MethodPost, "/api/v1/copilot/hook", strings.NewReader(string(raw)))
					req.Header.Set("Content-Type", "application/json")
					req.Header.Set("X-DefenseClaw-Copilot-Event", "preToolUse")
					req.Header.Set(hookpaths.Header, encodeTargets(t, targets))
					w := httptest.NewRecorder()
					api.handleAgentHook("copilot").ServeHTTP(w, req)
					var answer struct {
						Action  string   `json:"action"`
						RuleIDs []string `json:"rule_ids"`
					}
					if err := json.Unmarshal(w.Body.Bytes(), &answer); err != nil || w.Code != http.StatusOK {
						t.Fatalf("status=%d err=%v body=%s", w.Code, err, w.Body.String())
					}
					wantAction := "allow"
					if tc.blocks {
						wantAction = "block"
					}
					if tc.blocks && answer.Action != wantAction || !tc.blocks && answer.Action == "block" {
						t.Fatalf("action=%s, want %s; rules=%v", answer.Action, wantAction, answer.RuleIDs)
					}
					if tc.rule == "" && len(answer.RuleIDs) != 0 {
						t.Fatalf("ordinary call matched %v", answer.RuleIDs)
					}
					if tc.rule != "" && !slices.Contains(answer.RuleIDs, tc.rule) {
						t.Fatalf("rule %s absent: %v", tc.rule, answer.RuleIDs)
					}
				})
			}
		})
	}
}
