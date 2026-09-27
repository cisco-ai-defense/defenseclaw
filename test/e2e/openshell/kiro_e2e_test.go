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
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/harness"
	"github.com/defenseclaw/defenseclaw/internal/openshell/manager"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

const (
	// kiroMockScript is where a Kiro run's scripted turns are written in
	// the sandbox (KIRO_MOCK_CHAT_RESPONSE).
	kiroMockScript = "/tmp/dce2e-kiro-mock.json"
	// kiroPlaceholderKey only has to be present for Kiro's scripted mode.
	kiroPlaceholderKey = "dce2e-kiro-placeholder-not-a-secret"
	kiroAllowedFile    = "/tmp/dce2e-kiro-allowed.txt"
	kiroBlockedFile    = "/tmp/dce2e-kiro-blocked.txt"
)

// TestSandboxDaemonKiro drives one Kiro CLI sandbox through the daemon's
// REST API, with Kiro's own scripted-response mode in place of a model, to
// prove hook tamper detection for a harness whose hooks carry no per-call
// ID (DefenseClaw pairs Kiro's preToolUse and postToolUse by the call's
// session, tool name and input):
//
//   - real Kiro tool calls, one repeated with identical input, and a marker
//     call DefenseClaw denies, raise no hook_tamper;
//   - a postToolUse whose preToolUse never reached DefenseClaw (what a
//     killed preToolUse hook leaves) raises a hook_tamper alert naming
//     Kiro's preToolUse hook, and the open pack keeps the sandbox running;
//   - a call DefenseClaw denied whose postToolUse arrives anyway raises the
//     denied-ran-anyway alert.
//
// Opt-in like TestSandboxDaemon (same variables and cleanup):
//
//	DEFENSECLAW_E2E_WORK_DIR=/data/dc-openshell/scratch/e2e \
//	DEFENSECLAW_E2E_PREFIX=kiro-e2e \
//	go test -tags openshell_integration ./test/e2e/openshell/ -run TestSandboxDaemonKiro -v -timeout 60m
func TestSandboxDaemonKiro(t *testing.T) {
	work := os.Getenv("DEFENSECLAW_E2E_WORK_DIR")
	if work == "" {
		t.Skip("set DEFENSECLAW_E2E_WORK_DIR to run the live Kiro sandbox daemon test")
	}
	e := &env{
		t: t, root: t, prefix: envOr("DEFENSECLAW_E2E_PREFIX", "dc-e2e-kiro"),
		apiPort:       envInt(t, "DEFENSECLAW_E2E_API_PORT", 28970),
		mock:          envInt(t, "DEFENSECLAW_E2E_MOCK_PORT", 28921),
		tokenDelivery: e2eTokenDelivery(t),
		spec:          harness.Kiro,
	}
	if !openshell.ValidSandboxName(e.prefix) {
		t.Fatalf("DEFENSECLAW_E2E_PREFIX %q is not a valid sandbox name", e.prefix)
	}
	e.repo = repoRoot(t)
	e.work = filepath.Join(work, e.prefix)

	e.step("setup", e.setup)
	e.step("start daemon", e.startDaemon)
	sb := e.stepValue("create", e.kiroCreate)
	e.step("Kiro's own tool calls pair", func() { e.kiroToolCallsPair(sb) })
	e.step("a killed preToolUse hook raises an alert", func() { e.kiroTamperUnseen(sb) })
	e.step("a denied call that ran raises an alert", func() { e.kiroTamperDenied(sb) })
	e.step("delete", func() { e.deleteSandbox(sb) })
}

func (e *env) kiroCreate() *sandboxapi.Sandbox {
	t := e.t
	e.root.Cleanup(e.restDelete) // runs before the daemon stops
	started := time.Now()
	sb, err := e.api.Create(e.ctx(40*time.Minute), sandboxapi.CreateRequest{
		Name: e.prefix, Harness: harness.Kiro.Name, Project: e.project, Yolo: true,
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	t.Logf("created %s in %s: phase=%s pack=%s image=%s contract=%s tier=%s",
		sb.Name, time.Since(started).Round(time.Second), sb.Phase, sb.Pack, sb.Image, sb.HookContract, sb.TamperTier)
	if sb.Phase != "ready" || sb.Workdir == "" || sb.HookContract != "kiro-cli-hooks-v1" || sb.TamperTier != connector.SandboxTamperTierUser {
		t.Fatalf("created sandbox = %+v", sb)
	}
	got, err := e.gw.GetSandbox(e.ctx(30*time.Second), sb.Name)
	if err != nil || got.Labels[manager.LabelHarness] != harness.Kiro.Name {
		t.Fatalf("OpenShell sandbox %s = %+v, %v", sb.Name, got, err)
	}
	// A probe exec first: OpenShell 0.1.1 can hang the first exec after a
	// start, and the harness run must not be the one retried.
	e.exec(sb, 30*time.Second, true, "true")
	return sb
}

// kiroTurn is one scripted Kiro turn: a line of text and, unless command is
// empty, one shell tool call.
func kiroTurn(text, id, command string) []interface{} {
	turn := []interface{}{text}
	if command != "" {
		turn = append(turn, map[string]interface{}{
			"tool_use_id": id, "name": "shell", "args": map[string]string{"command": command},
		})
	}
	return turn
}

// kiroRun writes turns as Kiro's scripted response and runs one headless
// prompt through the in-image launcher, as `defenseclaw sandbox run -p`
// would (the launcher keeps KIRO_API_KEY and KIRO_MOCK_CHAT_RESPONSE).
func (e *env) kiroRun(sb *sandboxapi.Sandbox, prompt string, turns ...[]interface{}) string {
	e.t.Helper()
	script, err := json.Marshal(turns)
	if err != nil {
		e.t.Fatal(err)
	}
	// The script travels as an argument: exec stdin must stay closed.
	if res := e.exec(sb, 30*time.Second, true, "sh", "-c", `printf '%s' "$1" > "$2"`, "sh", string(script), kiroMockScript); res.code != 0 {
		e.t.Fatalf("write the Kiro script: exit %d %s", res.code, truncate(res.stdout, 200))
	}
	argv, err := harness.Kiro.LaunchArgv(harness.LaunchOptions{
		Mode: harness.Headless, Yolo: sb.Launch.Yolo, Prompt: prompt, CredentialProfile: sb.Launch.CredentialProfile,
	})
	if err != nil {
		e.t.Fatal(err)
	}
	argv = append([]string{"env", "KIRO_API_KEY=" + kiroPlaceholderKey, "KIRO_MOCK_CHAT_RESPONSE=" + kiroMockScript}, argv...)
	res, err := e.gw.Exec(e.ctx(5*time.Minute), sb.Name, argv, openshell.ExecOptions{WorkDir: sb.Workdir, Timeout: 4 * time.Minute})
	if err != nil {
		e.t.Fatalf("kiro %q: %v", prompt, err)
	}
	out := truncate(strings.TrimSpace(string(res.Stdout)), 400)
	if res.ExitCode != 0 {
		e.logSandbox(sb.Name)
		e.t.Fatalf("kiro %q exited %d: %s / %s", prompt, res.ExitCode, out, truncate(string(res.Stderr), 300))
	}
	e.t.Logf("kiro %q: %s", prompt, out)
	return out
}

// kiroToolCallsPair: Kiro's real hooks pair up. An allowed call, the same
// call again with identical input, and a marker call DefenseClaw denies
// (Kiro sends no postToolUse for it) are counted, and none of them is
// taken for tamper.
func (e *env) kiroToolCallsPair(sb *sandboxapi.Sandbox) {
	t := e.t
	before := e.waitHooks(sb.Name, func(sandboxapi.HookCoverage) bool { return true })
	allowed := "echo dce2e-kiro >> " + kiroAllowedFile
	e.kiroRun(sb, "Run the allowed Kiro check twice.",
		kiroTurn("Running the allowed Kiro check.", "dce2e-kiro-1", allowed),
		kiroTurn("Running it once more.", "dce2e-kiro-2", allowed),
		kiroTurn("Kiro check done.", "", ""),
	)
	if got := e.exec(sb, 30*time.Second, true, "cat", kiroAllowedFile); strings.Count(got.stdout, "dce2e-kiro") != 2 {
		t.Fatalf("%s = %q, want two lines from the two allowed calls", kiroAllowedFile, got.stdout)
	}
	e.kiroRun(sb, "Run the DefenseClaw marker command.",
		kiroTurn("Running the marker command.", "dce2e-kiro-3", "echo DCE2E-BLOCK-MARKER > "+kiroBlockedFile),
		kiroTurn("Marker command done.", "", ""),
	)
	if got := e.exec(sb, 30*time.Second, true, "sh", "-c", "test -e "+kiroBlockedFile+"; echo $?"); strings.TrimSpace(got.stdout) != "1" {
		t.Fatalf("the denied marker call ran: %s exists", kiroBlockedFile)
	}
	after := e.waitHooks(sb.Name, func(h sandboxapi.HookCoverage) bool {
		return h.ToolCalls >= before.ToolCalls+3 && h.ToolBlocked >= before.ToolBlocked+1
	})
	// Give a late post-tool decision time to land before reading tamper.
	time.Sleep(3 * time.Second)
	if h := e.get(sb.Name).Hooks; h.Tampered != 0 {
		t.Fatalf("real Kiro traffic raised hook tamper: %+v", h)
	}
	t.Logf("kiro hooks: tool_calls %d → %d, tool_blocked %d → %d, tampered 0",
		before.ToolCalls, after.ToolCalls, before.ToolBlocked, after.ToolBlocked)
}

// kiroHook runs the sandbox's Kiro hook by hand with one Kiro-shaped
// payload, as Kiro runs it, and returns its exit code.
func (e *env) kiroHook(sb *sandboxapi.Sandbox, event, session, command string) int {
	e.t.Helper()
	payload := map[string]interface{}{
		"hook_event_name": event, "cwd": sb.Workdir, "session_id": session,
		"tool_name": "shell", "tool_input": map[string]string{"command": command},
	}
	if event == "postToolUse" {
		payload["tool_response"] = map[string]interface{}{"items": []interface{}{map[string]string{"Text": "dce2e\n"}}}
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		e.t.Fatal(err)
	}
	// The payload travels as an argument: exec stdin must stay closed.
	script := `printf '%s' "$1" > /tmp/dce2e-kiro-hook.json && "$2" < /tmp/dce2e-kiro-hook.json`
	return e.exec(sb, time.Minute, false, "sh", "-c", script, "sh", string(raw), path.Join(connector.SandboxHookDir, "kiro-hook.sh")).code
}

func kiroTamperSession(t *testing.T) string {
	var raw [6]byte
	if _, err := rand.Read(raw[:]); err != nil {
		t.Fatal(err)
	}
	return "dce2e-kiro-tamper-" + hex.EncodeToString(raw[:])
}

// kiroTamperUnseen: a postToolUse whose preToolUse never reached DefenseClaw
// raises a hook_tamper alert; the open pack keeps the sandbox running.
func (e *env) kiroTamperUnseen(sb *sandboxapi.Sandbox) {
	t := e.t
	before := e.get(sb.Name).Hooks
	if code := e.kiroHook(sb, "postToolUse", kiroTamperSession(t), "echo DCE2E-TAMPER-MARKER"); code != 0 {
		t.Fatalf("the postToolUse hook exited %d", code)
	}
	ev := e.waitActivity(sb.Name, "hook_tamper on the feed", func(ev sandboxapi.ActivityEvent) bool {
		return ev.Kind == sandboxapi.ActivityFinding && ev.Reason == "hook_tamper" && ev.Tool == "shell" &&
			strings.Contains(ev.Message, "without a DefenseClaw verdict")
	})
	if ev.Severity != "HIGH" || ev.Event != "postToolUse" || !strings.Contains(ev.Message, "keeps running") {
		t.Fatalf("hook_tamper event = %+v, want a HIGH alert that keeps the sandbox running", ev)
	}
	after := e.waitHooks(sb.Name, func(h sandboxapi.HookCoverage) bool { return h.Tampered == before.Tampered+1 })
	time.Sleep(3 * time.Second)
	if got := e.get(sb.Name); got.Phase != "ready" {
		t.Fatalf("the open pack stopped the sandbox on hook tamper: phase %s", got.Phase)
	}
	e.noTamperTelemetryErrors()
	t.Logf("kiro hook tamper (unseen): tampered %d → %d, %q", before.Tampered, after.Tampered, ev.Message)
}

// kiroTamperDenied: a call DefenseClaw denied at preToolUse whose postToolUse
// arrives anyway raises the denied-ran-anyway alert.
func (e *env) kiroTamperDenied(sb *sandboxapi.Sandbox) {
	t := e.t
	before := e.get(sb.Name).Hooks
	session := kiroTamperSession(t)
	command := "echo DCE2E-BLOCK-MARKER dce2e-kiro-denied"
	if code := e.kiroHook(sb, "preToolUse", session, command); code != 2 {
		t.Fatalf("the preToolUse hook for the marker call exited %d, want 2 (denied)", code)
	}
	if code := e.kiroHook(sb, "postToolUse", session, command); code != 0 {
		t.Fatalf("the postToolUse hook exited %d", code)
	}
	ev := e.waitActivity(sb.Name, "denied hook_tamper on the feed", func(ev sandboxapi.ActivityEvent) bool {
		return ev.Kind == sandboxapi.ActivityFinding && ev.Reason == "hook_tamper" && strings.Contains(ev.Message, "although DefenseClaw denied it")
	})
	after := e.waitHooks(sb.Name, func(h sandboxapi.HookCoverage) bool { return h.Tampered == before.Tampered+1 })
	e.noTamperTelemetryErrors()
	t.Logf("kiro hook tamper (denied): tampered %d → %d, %q", before.Tampered, after.Tampered, ev.Message)
}
