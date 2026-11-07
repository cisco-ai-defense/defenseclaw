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
