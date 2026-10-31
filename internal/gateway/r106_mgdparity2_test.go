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
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// r106KeyReadVerdict judges one Bash call of the b36 fixture user, as a
// per-user gateway that can see the home or as the managed gateway behind
// ProtectHome (home hidden, verified hook peer), with the real hook client
// header either way. It returns "block", "alert" (observe mode, would block)
// or "allow".
func r106KeyReadVerdict(t *testing.T, f b36ManagedHookFixture, managed bool, connector, pack, mode, cwd, command string) string {
	t.Helper()
	payload := mustJSON(t, map[string]any{"session_id": "mgdp2", "hook_event_name": "PreToolUse", "cwd": cwd,
		"permission_mode": "default", "tool_name": "Bash", "tool_use_id": "toolu_mgdp2",
		"tool_input": map[string]any{"command": command, "description": "Run test fixture command"}})
	header := f.clientHeader(t, payload)
	if managed {
		if err := os.Chmod(f.homes, 0); err != nil {
			t.Fatal(err)
		}
		defer func() { _ = os.Chmod(f.homes, 0o700) }()
	}
	store, logger := testStoreAndLogger(t)
	cfg := &config.Config{}
	cfg.DataDir = os.Getenv("DEFENSECLAW_HOME")
	cfg.Guardrail.Mode = mode
	cfg.Guardrail.Connector = connector
	cfg.Guardrail.RulePackDir = filepath.Join(guardrailPoliciesRoot(t), pack)
	api := &APIServer{scannerCfg: cfg, store: store, logger: logger, health: NewSidecarHealth()}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/hook", strings.NewReader(string(payload)))
	req.Header.Set(hookpaths.Header, header)
	if connector == "codex" {
		setTestCodexHookBinding(req, "PreToolUse", defaultTestCodexHookContract)
	}
	if managed {
		req = req.WithContext(withManagedHookPeer(req.Context(), managedHookPeer{Home: f.home}))
	}
	recorder := httptest.NewRecorder()
	api.handleAgentHook(connector).ServeHTTP(recorder, req)
	var response map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("status %d body %.300s", recorder.Code, recorder.Body.String())
	}
	switch {
	case response["action"] == "block":
		return "block"
	case response["would_block"] == true:
		return "alert"
	}
	return "allow"
}

// TestR106ManagedPrivateKeyReadMatchesPerUser is rel-1-0-6:GAP-0179: the
// managed gateway cannot see the home (ProtectHome) and receives no cwd of
// its own, so a private-key read spelled relative to the directory the
// agent runs in (cat .ssh/id_ed25519 in the home, cat ../.ssh/id_rsa in a
// project) was not placed under ~/.ssh and was allowed, while a per-user
// gateway blocks it in action mode (PATH-SSH-KEY, default and strict packs,
// GAP-0124) and alerts in observe mode. The managed verdict must equal the
// per-user one: the reads block, and known_hosts, config, public keys,
// project files named like a key, a listing and the everyday key tools stay
// allowed in both.
func TestR106ManagedPrivateKeyReadMatchesPerUser(t *testing.T) {
	f := newB36ManagedHookFixture(t)
	// The data directory lies outside the home, as a managed gateway keeps
	// it: a data directory in the hidden home reads as an install window,
	// which the strict tier refuses whatever the call is.
	t.Setenv("DEFENSECLAW_HOME", t.TempDir())
	ssh := filepath.Join(f.home, ".ssh")
	for _, name := range []string{"id_ed25519", "id_rsa", "id_ecdsa"} {
		if err := os.WriteFile(filepath.Join(ssh, name), []byte("-----BEGIN OPENSSH PRIVATE KEY-----\ndecoy\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for name, body := range map[string]string{"id_ed25519.pub": "ssh-ed25519 AAAA decoy\n", "known_hosts": "host ssh-ed25519 AAAA\n", "config": "Host x\n"} {
		if err := os.WriteFile(filepath.Join(ssh, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(filepath.Join(f.project, "keys"), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"id_rsa", filepath.Join("keys", "id_rsa"), "README.md"} {
		if err := os.WriteFile(filepath.Join(f.project, name), []byte("fixture\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	type row struct {
		id, where, command string
		block              bool
	}
	rows := []row{
		{"K1", "h", "cat .ssh/id_ed25519", true},
		{"K2", "h", "cat .ssh/id_ed25519 2>/dev/null", true},
		{"K3", "h", "cat .ssh/id_ed25519 >& /dev/null", true},
		{"K4", "h", "head -n 5 .ssh/id_rsa", true},
		{"K5", "h", "base64 .ssh/id_ecdsa", true},
		{"K6", "p", "cat ../.ssh/id_rsa", true},
		{"K7", "h", "cat ./.ssh/id_ed25519", true},
		{"K8", "h", "cat ~/.ssh/id_ed25519", true},
		{"N1", "h", "cat .ssh/known_hosts", false},
		{"N2", "h", "cat .ssh/config", false},
		{"N3", "h", "cat .ssh/id_ed25519.pub", false},
		{"N4", "p", "cat id_rsa", false},
		{"N5", "p", "cat keys/id_rsa", false},
		{"N6", "h", "cat project/id_rsa", false},
		{"N7", "h", "ls -l .ssh", false},
		{"N8", "h", "ssh-keygen -y -f .ssh/id_ed25519", false},
		{"N9", "p", "cat ../.ssh/id_ed25519.pub", false},
		{"N10", "p", "cat README.md", false},
	}
	for _, pack := range []string{"default", "strict"} {
		for _, mode := range []string{"action", "observe"} {
			for _, connector := range []string{"claudecode", "codex"} {
				for _, r := range rows {
					cwd := f.project
					if r.where == "h" {
						cwd = f.home
					}
					want := "allow"
					if r.block && mode == "action" {
						want = "block"
					} else if r.block {
						want = "alert"
					}
					perUser := r106KeyReadVerdict(t, f, false, connector, pack, mode, cwd, r.command)
					managed := r106KeyReadVerdict(t, f, true, connector, pack, mode, cwd, r.command)
					if perUser != want {
						t.Errorf("%s %s/%s/%s %q: per-user %s, want %s (fixture premise)", r.id, pack, mode, connector, r.command, perUser, want)
					}
					if managed != perUser {
						t.Errorf("%s %s/%s/%s %q: managed %s, per-user %s", r.id, pack, mode, connector, r.command, managed, perUser)
					}
				}
			}
		}
	}
}
