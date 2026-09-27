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

//go:build openshell_integration && (linux || darwin)

package openshelle2e

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/openshell/harness"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

// TestSandboxHookOnlyHarness drives one Hermes, OpenHands, Antigravity or
// OmniGent sandbox through the daemon the way TestSandboxDaemon drives Claude
// Code, with mock_chat.py (OpenAI Chat Completions and Responses, Gemini)
// standing in for the model behind a --credential binding on
// host.openshell.internal:
//
//   - create (overlay image build and hook-fire verification when missing);
//   - an allowed tool call whose hooks reach the sandbox ingress, with the
//     model key substituted by OpenShell on the way to the mock;
//   - the marker command the test guardrail rule blocks, denied by the
//     harness's own hook with the plain reason;
//   - egress through the DefenseClaw proxy: an allowed host, the harness's
//     own fetch, a blocklisted host and a sandbox-scoped unblock;
//   - delete.
//
// Opt-in, like TestSandboxDaemon:
//
//	DEFENSECLAW_E2E_WORK_DIR=/data/dc-openshell/scratch/e2e \
//	DEFENSECLAW_E2E_PREFIX=h3-e2e-hermes DEFENSECLAW_E2E_HARNESS=hermes \
//	go test -tags openshell_integration ./test/e2e/openshell/ -run TestSandboxHookOnlyHarness -v -timeout 60m
func TestSandboxHookOnlyHarness(t *testing.T) {
	work := os.Getenv("DEFENSECLAW_E2E_WORK_DIR")
	name := os.Getenv("DEFENSECLAW_E2E_HARNESS")
	if work == "" || name == "" {
		t.Skip("set DEFENSECLAW_E2E_WORK_DIR and DEFENSECLAW_E2E_HARNESS (hermes, openhands, antigravity or omnigent)")
	}
	wiring, ok := hookOnlyWirings[name]
	if !ok {
		t.Fatalf("DEFENSECLAW_E2E_HARNESS %q has no E2E wiring", name)
	}
	spec, ok := harness.Get(name)
	if !ok {
		t.Fatalf("harness %q is not registered", name)
	}
	e := &env{
		t: t, root: t, prefix: envOr("DEFENSECLAW_E2E_PREFIX", "dc-e2e-"+name),
		apiPort: envInt(t, "DEFENSECLAW_E2E_API_PORT", 28970),
		mock:    envInt(t, "DEFENSECLAW_E2E_MOCK_PORT", 28921),
		spec:    spec, launchArgs: wiring.args,
		mockModel: "mock_chat.py", mockScript: "daemon-hookonly.json",
		tokenDelivery: e2eTokenDelivery(t),
	}
	e.repo = repoRoot(t)
	e.work = filepath.Join(work, e.prefix)

	e.step("setup", e.setup)
	e.step("start daemon", e.startDaemon)
	sb := e.stepValue("create", func() *sandboxapi.Sandbox { return e.createHookOnly(wiring) })
	e.step("hook reaches the ingress", func() { e.hookOnlyReachesIngress(sb) })
	e.step("DefenseClaw blocks the marker command", func() { e.hookOnlyBlocked(sb, wiring) })
	e.step("egress through the proxy", func() { e.egressThroughProxy(sb) })
	e.step("destinations the harness reached", func() { e.egressDiscovery(sb) })
	e.step("delete", func() { e.deleteSandbox(sb) })
}

// egressDiscovery logs every destination the sandbox reached or was refused,
// through the DefenseClaw proxy or directly (OpenShell), so a harness's
// startup traffic (update checks, telemetry, skill downloads) is on record
// next to the hosts the test itself fetched.
func (e *env) egressDiscovery(sb *sandboxapi.Sandbox) {
	t := e.t
	seen := map[string]int{}
	err := e.api.Activity(e.ctx(30*time.Second), sandboxapi.ActivityQuery{Sandbox: sb.Name}, func(ev sandboxapi.ActivityEvent) error {
		switch ev.Kind {
		case sandboxapi.ActivityEgressAllowed, sandboxapi.ActivityEgressBlocked, sandboxapi.ActivityApprovalRequested:
			seen[ev.Kind+" "+ev.Source+" "+ev.Host+":"+strconv.Itoa(ev.Port)]++
		}
		return nil
	})
	if err != nil {
		t.Fatalf("activity: %v", err)
	}
	keys := make([]string, 0, len(seen))
	for k := range seen {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		t.Logf("egress: %s ×%d", k, seen[k])
	}
}

// hookOnlyWiring points one harness at the mock model through a credential
// binding: the harness variable that carries the key, the endpoint
// variables and the launch arguments that select the endpoint.
type hookOnlyWiring struct {
	credential string
	env        func(mockURL string) map[string]string
	args       []string
}

var hookOnlyWirings = map[string]hookOnlyWiring{
	"hermes": {
		credential: connector.HermesSandboxProviderKeyEnv,
		env: func(u string) map[string]string {
			return map[string]string{connector.HermesSandboxProviderBaseURLEnv: u + "/v1"}
		},
		args: []string{"--provider", connector.HermesSandboxProviderName, "-m", "mock-model"},
	},
	"openhands": {
		credential: "LLM_API_KEY",
		env: func(u string) map[string]string {
			return map[string]string{"LLM_MODEL": "openai/mock-model", "LLM_BASE_URL": u + "/v1"}
		},
		args: []string{"--override-with-envs"},
	},
	"antigravity": {
		credential: "GEMINI_API_KEY",
		env:        func(u string) map[string]string { return map[string]string{"GOOGLE_GEMINI_BASE_URL": u} },
	},
	// The image's sandbox agent on the openai-agents harness (Responses).
	"omnigent": {
		credential: "OPENAI_API_KEY",
		env:        func(u string) map[string]string { return map[string]string{"OPENAI_BASE_URL": u + "/v1"} },
		args:       []string{connector.OmnigentSandboxAgentPath, "--model", "mock-model"},
	},
}

func (e *env) createHookOnly(w hookOnlyWiring) *sandboxapi.Sandbox {
	t := e.t
	e.root.Cleanup(e.restDelete)
	started := time.Now()
	mockURL := "http://" + connector.SandboxIngressHost + ":" + strconv.Itoa(e.mock)
	sb, err := e.api.Create(e.ctx(40*time.Minute), sandboxapi.CreateRequest{
		Name: e.prefix, Harness: e.spec.Name, Project: e.project,
		Credentials: []sandboxapi.CredentialBinding{{Name: w.credential, Value: mockKey, Host: connector.SandboxIngressHost, Port: e.mock}},
		Env:         w.env(mockURL),
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	ctx := e.ctx(30 * time.Second)
	e.recordProfiles(ctx, e.prefixedProviders(ctx))
	t.Logf("created %s in %s: phase=%s pack=%s profile=%s mode=%s image=%s contract=%s tier=%s",
		sb.Name, time.Since(started).Round(time.Second), sb.Phase, sb.Pack, sb.Profile, sb.WorkdirMode, sb.Image,
		sb.HookContract, sb.TamperTier)
	if sb.Phase != "ready" || sb.WorkdirMode != "mount" || sb.TamperTier != e.spec.TamperTier || sb.HookContract == "" {
		t.Fatalf("created sandbox = %+v", sb)
	}
	e.exec(sb, 30*time.Second, true, "true")
	return sb
}

func (e *env) hookOnlyReachesIngress(sb *sandboxapi.Sandbox) {
	t := e.t
	before := e.get(sb.Name).Hooks
	out := e.harness(sb, "Write the allowed marker file.")
	if got := e.exec(sb, 30*time.Second, true, "cat", allowedMarkerFile); strings.TrimSpace(got.stdout) != "dce2e-allowed" {
		t.Fatalf("allowed tool call left %q in %s (harness said %q)", got.stdout, allowedMarkerFile, out)
	}
	after := e.waitHooks(sb.Name, func(h sandboxapi.HookCoverage) bool {
		return h.HookRequests > before.HookRequests && h.ToolCalls > before.ToolCalls && !h.LastHookAt.IsZero()
	})
	t.Logf("hooks: requests %d → %d, tool calls %d → %d, last hook %s", before.HookRequests, after.HookRequests,
		before.ToolCalls, after.ToolCalls, after.LastHookAt.Format(time.RFC3339))
	calls, substituted, placeholder := mockChatAuth(filepath.Join(e.work, "logs", "mock.jsonl"))
	if calls == 0 || substituted == 0 || placeholder != 0 {
		t.Fatalf("mock model: %d model calls, %d with the key substituted, %d with a placeholder", calls, substituted, placeholder)
	}
	t.Logf("mock model: %d model calls, every key substituted by OpenShell; tool calls %q", calls,
		mockChatCalls(filepath.Join(e.work, "logs", "mock.jsonl")))
	if after.Tampered != 0 {
		t.Fatalf("real harness traffic raised hook tamper: %+v", after)
	}
}

func (e *env) hookOnlyBlocked(sb *sandboxapi.Sandbox, w hookOnlyWiring) {
	t := e.t
	before := e.get(sb.Name).Hooks
	out := e.harness(sb, "Run the DCE2E-DENY scenario.")
	if res := e.exec(sb, 30*time.Second, true, "test", "-e", blockedMarkerFile); res.code == 0 {
		t.Fatalf("the blocked command ran: %s exists (harness said %q); tool calls: %q; hook activity: %q", blockedMarkerFile, out,
			mockChatCalls(filepath.Join(e.work, "logs", "mock.jsonl")), e.hookActivity(sb))
	}
	after := e.waitHooks(sb.Name, func(h sandboxapi.HookCoverage) bool { return h.ToolBlocked > before.ToolBlocked })
	if !strings.HasPrefix(after.LastBlocked, blockedReason) || strings.Contains(after.LastBlocked, "<redacted") {
		t.Fatalf("last blocked reason = %q, want it to start with %q", after.LastBlocked, blockedReason)
	}
	ev := e.waitActivity(sb.Name, "tool.blocked on the feed", func(ev sandboxapi.ActivityEvent) bool {
		return ev.Kind == sandboxapi.ActivityToolBlocked && strings.HasPrefix(ev.Reason, blockedReason)
	})
	var told string
	for _, r := range mockChatToolResults(filepath.Join(e.work, "logs", "mock.jsonl")) {
		if strings.Contains(r, "E2E-SANDBOX-MARKER") {
			told = r
		}
	}
	t.Logf("blocked: tool_blocked %d → %d; feed %q (tool %q); the model was told %q; harness said %q",
		before.ToolBlocked, after.ToolBlocked, ev.Message, ev.Tool, truncate(told, 200), out)
	if told == "" {
		t.Fatalf("the model was never told why the marker command was blocked")
	}
	if after.Tampered != 0 {
		t.Fatalf("a denied tool call raised hook tamper: %+v", after)
	}
}

// hookActivity lists the sandbox's hook-side feed events (event, tool,
// severity, reason, message), for a failure message.
func (e *env) hookActivity(sb *sandboxapi.Sandbox) []string {
	var out []string
	err := e.api.Activity(e.ctx(30*time.Second), sandboxapi.ActivityQuery{Sandbox: sb.Name}, func(ev sandboxapi.ActivityEvent) error {
		if ev.Event != "" || ev.Tool != "" {
			out = append(out, strings.Join([]string{ev.Kind, ev.Event, ev.Tool, ev.Severity, ev.Reason, truncate(ev.Message, 160)}, " | "))
		}
		return nil
	})
	if err != nil {
		out = append(out, "activity: "+err.Error())
	}
	return out
}

// mockChatAuth counts mock_chat.py's model calls and how their credential
// header arrived: substituted by OpenShell ("[redacted]") or still a
// placeholder.
func mockChatAuth(path string) (calls, substituted, placeholder int) {
	for _, rec := range mockChatRecords(path) {
		if rec.Plan == nil {
			continue
		}
		calls++
		for k, v := range rec.Headers {
			switch strings.ToLower(k) {
			case "authorization", "x-goog-api-key", "x-api-key", "api-key":
			default:
				continue
			}
			switch {
			case strings.HasSuffix(v, "[redacted placeholder]"):
				placeholder++
			case strings.HasSuffix(v, "[redacted]"):
				substituted++
			}
		}
	}
	return calls, substituted, placeholder
}

// mockChatToolResults returns every tool result the harness reported to the
// mock model.
func mockChatToolResults(path string) []string {
	var out []string
	for _, rec := range mockChatRecords(path) {
		out = append(out, rec.ToolResults...)
	}
	return out
}

type mockChatRecord struct {
	Path        string            `json:"path"`
	Headers     map[string]string `json:"headers"`
	ToolResults []string          `json:"tool_results"`
	Plan        *struct {
		Scenario string `json:"scenario"`
		Reply    string `json:"reply"`
		Call     *struct {
			Name   string          `json:"name"`
			Args   string          `json:"args"`
			Schema json.RawMessage `json:"schema"`
		} `json:"call"`
	} `json:"plan"`
}

// mockChatCalls returns the shell tool calls the mock model made, with the
// tool's parameter names, so a command that ran anyway shows the exact
// arguments the hook was asked about.
func mockChatCalls(path string) []string {
	var out []string
	for _, rec := range mockChatRecords(path) {
		if rec.Plan != nil && rec.Plan.Call != nil {
			out = append(out, rec.Plan.Call.Name+" "+rec.Plan.Call.Args+" "+string(rec.Plan.Call.Schema))
		}
	}
	return out
}

func mockChatRecords(path string) []mockChatRecord {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []mockChatRecord
	s := bufio.NewScanner(f)
	s.Buffer(make([]byte, 0, 64<<10), 4<<20)
	for s.Scan() {
		var rec mockChatRecord
		if json.Unmarshal(s.Bytes(), &rec) == nil {
			out = append(out, rec)
		}
	}
	return out
}
