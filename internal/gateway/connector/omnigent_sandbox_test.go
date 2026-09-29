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

package connector

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"

	"gopkg.in/yaml.v3"
)

// TestOmnigentSandboxArtifacts: the root-owned configuration loads only the
// DefenseClaw policy module, switches OmniGent's usage telemetry off (it
// called config.omnigent-telemetry.io and api.omnigent-telemetry.io at every
// start, OG-U3) and pins the TUI theme (without one the TUI's first-launch
// picker crashes writing it to the root-owned file, R2-79).
func TestOmnigentSandboxArtifacts(t *testing.T) {
	var cfg map[string]interface{}
	artifacts := sandboxArtifactsFor(t, NewOmnigentConnector(), "0.13.0")
	if module := sandboxFile(t, artifacts, OmnigentSandboxPolicyModulePath).Data; strings.Contains(string(module), "{{API_ADDR_B64}}") || strings.Contains(string(module), "{{FAIL_MODE_B64}}") {
		t.Fatal("sandbox policy carries unrendered template tokens")
	}
	config := sandboxFile(t, artifacts, OmnigentSandboxConfigPath).Data
	if err := yaml.Unmarshal(config, &cfg); err != nil {
		t.Fatal(err)
	}
	if modules := cfg["policy_modules"].([]interface{}); len(modules) != 1 || modules[0] != omnigentPolicyModuleName {
		t.Fatalf("policy_modules = %v", cfg["policy_modules"])
	}
	if tui, _ := cfg["tui"].(map[string]interface{}); tui["theme"] != "dark" {
		t.Fatalf("tui = %v, want a pinned theme", cfg["tui"])
	}
	if cfg["telemetry"] != false {
		t.Fatalf("telemetry = %v, want false", cfg["telemetry"])
	}
	// OmniGent reads the switch with a line match on the raw text, not
	// through its YAML loader (telemetry/client.py _config_telemetry_disabled).
	if !regexp.MustCompile(`(?im)^\s*telemetry\s*:\s*false\s*$`).Match(config) {
		t.Fatalf("OmniGent would not see telemetry switched off in:\n%s", config)
	}
	if err := verifyOmnigentSandboxConfig(config); err != nil {
		t.Fatalf("rendered config rejected: %v", err)
	}
	// OmniGent's TUI hides tool results, the only place a deny reason
	// shows, so the sandbox agent tells the model to pass it on (OG-U1).
	var agent struct {
		Name   string `yaml:"name"`
		Prompt string `yaml:"prompt"`
	}
	if err := yaml.Unmarshal(sandboxFile(t, artifacts, filepath.Join(OmnigentSandboxAgentPath, "config.yaml")).Data, &agent); err != nil {
		t.Fatal(err)
	}
	prompt := strings.Join(strings.Fields(agent.Prompt), " ")
	for _, want := range []string{"denied by policy", "tell the user that DefenseClaw blocked it", "word for word"} {
		if !strings.Contains(prompt, want) {
			t.Errorf("sandbox agent prompt lacks %q:\n%s", want, agent.Prompt)
		}
	}
	telemetryOn := omnigentSandboxConfig()
	telemetryOn["telemetry"] = true
	telemetryOnYAML, err := yaml.Marshal(telemetryOn)
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"policy_modules: []\n", "policy_modules: [x]\npolicies: {}\n", "{", string(telemetryOnYAML)} {
		if err := verifyOmnigentSandboxConfig([]byte(bad)); err == nil {
			t.Fatalf("verify accepted %q", bad)
		}
	}
}

// omnigentIngress stands in for the sandbox ingress: it answers each request
// with the next scripted (status, body) and records what it received.
type omnigentIngress struct {
	mu       sync.Mutex
	replies  []omnigentReply
	requests []omnigentRequest
}

type omnigentRequest struct{ auth, key, body, path string }

type omnigentReply struct {
	status int
	body   string
}

func (s *omnigentIngress) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	raw, _ := io.ReadAll(r.Body)
	s.mu.Lock()
	reply := omnigentReply{status: 500, body: "{}"}
	if len(s.requests) < len(s.replies) {
		reply = s.replies[len(s.requests)]
	}
	s.requests = append(s.requests, omnigentRequest{r.Header.Get("Authorization"), r.Header.Get("X-DefenseClaw-Hook-Idempotency-Key"), string(raw), r.URL.Path})
	s.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(reply.status)
	_, _ = io.WriteString(w, reply.body)
}

func TestOmnigentSandboxPolicyTransport(t *testing.T) {
	python := omnigentTestPython(t)
	template, err := hookFS.ReadFile("hooks/omnigent-policy.py")
	if err != nil {
		t.Fatal(err)
	}
	tail, err := hookFS.ReadFile("hooks/omnigent-policy-sandbox.py")
	if err != nil {
		t.Fatal(err)
	}
	keyRE := regexp.MustCompile(`^[0-9a-f]{32}$`)
	event := `{"type": "tool_call", "target": "bash", "data": {"name": "bash", "arguments": {"command": "ls"}}, "context": {}}`
	script := `
import importlib.util, json, sys
spec = importlib.util.spec_from_file_location("defenseclaw_omnigent_policy", sys.argv[1])
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
print(json.dumps(module.defenseclaw_policy(json.loads(sys.argv[2]))))
`
	cases := []struct {
		name      string
		token     string
		replies   []omnigentReply
		down      bool
		result    string
		reason    string
		wantCalls int
	}{
		{"allow", "tok", []omnigentReply{{200, `{"action":"allow"}`}}, false, "ALLOW", "", 1},
		{"alert-allows", "tok", []omnigentReply{{200, `{"action":"alert"}`}}, false, "ALLOW", "", 1},
		{"block", "tok", []omnigentReply{{200, `{"action":"block","reason":"rule X"}`}}, false, "DENY", "rule X", 1},
		// OmniGent's approval routes are open to the whole sandbox, so a
		// confirm verdict denies instead of parking an ASK.
		{"confirm-denies", "tok", []omnigentReply{{200, `{"action":"confirm","reason":"ask me"}`}}, false, "DENY", "ask me Approval is not available for OmniGent in a DefenseClaw sandbox", 1},
		{"relay-502-retried", "tok", []omnigentReply{{502, `{}`}, {200, `{"action":"allow"}`}}, false, "ALLOW", "", 2},
		{"relay-502-twice", "tok", []omnigentReply{{502, `{}`}, {503, `{}`}}, false, "DENY", "failed closed", 2},
		{"unauthorized-not-retried", "tok", []omnigentReply{{401, `{"error":"bad token"}`}}, false, "DENY", "failed closed", 1},
		{"unknown-action", "tok", []omnigentReply{{200, `{"action":"maybe"}`}}, false, "DENY", "failed closed", 1},
		{"not-json", "tok", []omnigentReply{{200, `<html>`}}, false, "DENY", "failed closed", 1},
		{"empty-2xx", "tok", []omnigentReply{{204, ``}}, false, "DENY", "failed closed", 1},
		{"no-token", "", []omnigentReply{{200, `{"action":"allow"}`}}, false, "DENY", "binding token is unavailable", 0},
		{"malformed-token", "a\nb", []omnigentReply{{200, `{"action":"allow"}`}}, false, "DENY", "binding token is unavailable", 0},
		{"ingress-down", "tok", nil, true, "DENY", "failed closed", 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ingress := &omnigentIngress{replies: tc.replies}
			srv := httptest.NewServer(ingress)
			defer srv.Close()
			addr := strings.TrimPrefix(srv.URL, "http://")
			if tc.down {
				l, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				addr = l.Addr().String()
				_ = l.Close()
			}
			module := renderOmnigentPolicy(string(template), addr, "", "closed") + string(tail)
			path := filepath.Join(t.TempDir(), "defenseclaw_omnigent_policy.py")
			if err := os.WriteFile(path, []byte(module), 0o600); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(python, "-I", "-c", script, path, event)
			cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=" + t.TempDir()}
			if tc.token != "" {
				cmd.Env = append(cmd.Env, SandboxTokenEnv+"="+tc.token)
			}
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("policy: %v\n%s", err, out)
			}
			var verdict map[string]string
			if err := json.Unmarshal(out, &verdict); err != nil {
				t.Fatalf("verdict %q: %v", out, err)
			}
			if verdict["result"] != tc.result || !strings.Contains(verdict["reason"], tc.reason) {
				t.Fatalf("verdict = %v, want %s containing %q", verdict, tc.result, tc.reason)
			}
			if len(ingress.requests) != tc.wantCalls {
				t.Fatalf("ingress calls = %d, want %d", len(ingress.requests), tc.wantCalls)
			}
			for i, req := range ingress.requests {
				if req.auth != "Bearer "+tc.token || !keyRE.MatchString(req.key) || req.key != ingress.requests[0].key ||
					req.path != "/api/v1/omnigent/hook" || !strings.Contains(req.body, `"hook_event_name":"PreToolUse"`) {
					t.Fatalf("call %d: %+v", i, req)
				}
			}
		})
	}
}
