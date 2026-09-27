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
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/harness"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

// TestSandboxTUICodex certifies the interactive Codex TUI in a DefenseClaw
// sandbox, next to `codex exec`, because hooks do not behave the same way in
// both: some events only fire interactively, and login, trust and approval
// screens exist only in the TUI. A real terminal comes from tmux: the test
// types `defenseclaw-gateway sandbox run codex` into a shell in a detached
// tmux session, sends keystrokes with send-keys and reads the screen with
// capture-pane, waiting on what the screen or DefenseClaw's audit log shows.
// The mock Responses server (mock_openai.py, scenarios/tui-codex.json) stands
// in for the model behind Codex's built-in OpenAI provider (openai_base_url),
// the path that needs the launcher's `codex login --with-api-key`.
//
//   - launch: no login, onboarding or trust screen (the launcher logs in with
//     the credential placeholder and trusts the exact project path), YOLO
//     mode; without the launcher the same Codex shows its sign-in screen, and
//     in a folder the launcher does not trust, its trust screen;
//   - hooks: every event the connector registers reaches the sandbox ingress
//     (SessionStart, UserPromptSubmit, PreToolUse, PermissionRequest,
//     PostToolUse, SubagentStart, SubagentStop, PreCompact, PostCompact,
//     Stop, SessionEnd, and the notify bridge), counted from the audit log
//     per mode;
//   - a DefenseClaw-blocked marker command: denied, with the reason on the
//     screen and in what the model is told;
//   - hook tamper during a live TUI session: a PostToolUse for a harmless
//     marker call whose PreToolUse never reached DefenseClaw raises
//     hook_tamper, and the session keeps working;
//   - Ctrl-Z leaves the TUI running, /exit and Ctrl-C end the session with the
//     summary, and the keep/undo prompt shows the diff and undoes the edit;
//   - --safe keeps Codex's approval prompt (and PermissionRequest), which the
//     skip-permissions run does not show for the same command;
//   - the shell wrapper: typing `codex` in a wrapped bash resumes the
//     folder's sandbox;
//   - DEFENSECLAW_E2E_BEDROCK=1 adds a short TUI session on Amazon Bedrock
//     (openai.gpt-oss-20b; AWS_BEARER_TOKEN_BEDROCK must hold a short-term
//     key).
//
// The hook matrix (event × headless/TUI) is logged at the end. tmux must be
// on PATH; the test skips without it.
//
//	DEFENSECLAW_E2E_WORK_DIR=/data/dc-openshell/scratch/e2e DEFENSECLAW_E2E_PREFIX=tuicx \
//	go test -tags openshell_integration ./test/e2e/openshell/ -run TestSandboxTUICodex -v -timeout 90m
func TestSandboxTUICodex(t *testing.T) {
	work := os.Getenv("DEFENSECLAW_E2E_WORK_DIR")
	if work == "" {
		t.Skip("set DEFENSECLAW_E2E_WORK_DIR to run the live Codex TUI test")
	}
	tmux, err := exec.LookPath("tmux")
	if err != nil {
		t.Skip("tmux is needed to give the Codex TUI a real terminal")
	}
	e := &env{
		t: t, root: t, prefix: envOr("DEFENSECLAW_E2E_PREFIX", "dc-e2e") + "-tui",
		apiPort:       envInt(t, "DEFENSECLAW_E2E_API_PORT", 28970) + 300,
		mock:          envInt(t, "DEFENSECLAW_E2E_MOCK_PORT", 28921) + 300,
		tokenDelivery: e2eTokenDelivery(t),
	}
	if !openshell.ValidNewSandboxName(e.prefix + "-y") {
		t.Fatalf("DEFENSECLAW_E2E_PREFIX %q does not make sandbox names OpenShell creates (at most %d characters)", e.prefix, openshell.MaxSandboxNameLen)
	}
	e.repo = repoRoot(t)
	e.work = filepath.Join(work, e.prefix)
	x := &tuiCodex{
		cliEnv: &cliEnv{env: e, openaiPort: e.mock + 1}, tmux: tmux,
		yolo: e.prefix + "-y", safe: e.prefix + "-s", bedrock: e.prefix + "-b",
		seen: map[string]map[string]int{modeHeadless: {}, modeTUI: {}},
	}

	e.step("setup", func() { e.setup(); x.setup() })
	e.step("start daemon", e.startDaemon)
	e.step("TUI starts without dialogs", x.launch)
	e.step("TUI allowed tool call", x.allowed)
	e.step("TUI DefenseClaw block", x.blocked)
	e.step("TUI skip-permissions runs without a prompt", x.noPrompt)
	e.step("TUI sub-agent", x.subagent)
	e.step("TUI compaction", x.compact)
	e.step("TUI hook tamper alert", x.tamper)
	e.step("TUI Ctrl-Z", x.ctrlZ)
	e.step("TUI exit, summary and undo", x.exitUndo)
	e.step("headless codex exec", x.headless)
	e.step("dialogs without the launcher", x.dialogs)
	e.step("TUI --safe approval prompt", x.safeRun)
	e.step("shell wrapper", x.wrapper)
	if os.Getenv("DEFENSECLAW_E2E_BEDROCK") == "1" {
		e.step("bedrock TUI", x.bedrockTUI)
	}
	e.step("hook matrix", x.matrix)
	e.step("delete", x.deleteAll)
}

const (
	modeHeadless = "headless"
	modeTUI      = "tui"
	// notifyEvent is the matrix row of the Codex notify bridge (audited as a
	// synthetic Stop).
	notifyEvent = "notify"
	// shellPrompt is PS1 of the shells in the tmux sessions.
	shellPrompt = "dce2e-shell$"
	codexBanner = "OpenAI Codex (v"
	approvalAsk = "Would you like to run the following command?"
)

// codexEvents are the rows of the hook matrix: the events the Codex
// connector registers in the sandbox image (contract codex-hooks-v4) and the
// notify bridge.
var codexEvents = []string{"SessionStart", "UserPromptSubmit", "PreToolUse", "PermissionRequest", "PostToolUse",
	"SubagentStart", "SubagentStop", "PreCompact", "PostCompact", "Stop", "SessionEnd", notifyEvent}

type tuiCodex struct {
	*cliEnv
	tmux                string
	yolo, safe, bedrock string
	terms               []*tmuxTerm
	screens             int
	seen                map[string]map[string]int
	blockedShown        map[string]bool
	sessionStartMissing []string
	tamperHit           bool
	tokenEnv            bool
	// unaudited counts verdicts per mode and event that got no
	// connector-hook audit row.
	unaudited map[string]int
}

func (x *tuiCodex) setup() {
	t := x.t
	cfgPath := filepath.Join(x.work, "dc", "config.yaml")
	raw, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	cfg := strings.Replace(string(raw), "harnesses: [claudecode]", "harnesses: [codex]", 1)
	// DEFENSECLAW_E2E_TOKEN_DELIVERY=env delivers the binding token itself
	// in the environment (every daemon has an ingress profile of its own
	// port, so the default provider delivery needs no fallback).
	x.tokenEnv = x.tokenDelivery == config.OpenShellTokenDeliveryEnv
	writeFile(t, cfgPath, []byte(cfg), 0o600)

	px := x.spawn("mock-openai", "python3", filepath.Join(x.repo, "test", "e2e", "openshell", "mock_openai.py"),
		"--host", "127.0.0.1", "--port", strconv.Itoa(x.openaiPort), "--quiet",
		"--log", filepath.Join(x.work, "logs", "mock-openai.jsonl"),
		"--script", filepath.Join(x.repo, "test", "e2e", "openshell", "scenarios", "tui-codex.json"))
	x.root.Cleanup(func() { stop(px) })
	waitFor(t, 20*time.Second, "the mock Responses server", func() error {
		return httpGet("http://127.0.0.1:" + strconv.Itoa(x.openaiPort) + "/v1/models")
	})
	if err := os.MkdirAll(filepath.Join(x.work, "logs", "screens"), 0o700); err != nil {
		t.Fatal(err)
	}
	// The terminals go first (registered last), then the sandboxes: the
	// daemon, started later, is gone by then, so leftovers go through the
	// gateway.
	x.root.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		for _, name := range []string{x.yolo, x.safe, x.bedrock} {
			if _, err := x.gw.GetSandbox(ctx, name); err != nil {
				continue
			}
			x.root.Logf("cleanup: deleting leftover sandbox %s", name)
			if _, err := x.gw.DeleteSandbox(ctx, name); err != nil {
				x.root.Logf("cleanup: delete sandbox %s: %v", name, err)
			} else if err := x.gw.WaitDeleted(ctx, name); err != nil {
				x.root.Logf("cleanup: wait for %s: %v", name, err)
			}
		}
	})
	x.root.Cleanup(func() {
		for _, m := range x.terms {
			m.close()
		}
	})
}

// ---- the skip-permissions TUI session -------------------------------------------

func (x *tuiCodex) mockArgs() []string {
	return []string{"-c", "openai_base_url=http://host.openshell.internal:" + strconv.Itoa(x.openaiPort) + "/v1", "-m", "mock-model"}
}

func (x *tuiCodex) runArgs(name string, extra ...string) []string {
	args := []string{filepath.Join(x.work, "bin", "defenseclaw-gateway"), "sandbox", "run", "codex", "--name", name,
		"--llm", "none", "--credential", "OPENAI_API_KEY=host.openshell.internal:" + strconv.Itoa(x.openaiPort)}
	args = append(append(args, extra...), "--")
	return append(args, x.mockArgs()...)
}

func (x *tuiCodex) launch() {
	t := x.t
	m := x.term("yolo", nil)
	m.line(shellJoin(x.runArgs(x.yolo)...))
	// The first run builds the overlay image.
	screen := m.waitFor(45*time.Minute, "the Codex TUI", func(s string) bool {
		return strings.Contains(s, codexBanner) && strings.Contains(s, "directory:") && strings.Contains(s, "› ")
	})
	for _, want := range []string{"Sandbox " + x.yolo + " · Codex · skip-permissions ON", "permissions: YOLO mode", "/work/"} {
		if !strings.Contains(screen, want) {
			t.Fatalf("launch screen lacks %q:\n%s", want, screen)
		}
	}
	for _, dialog := range []string{"Sign in with ChatGPT", "Provide your own API key", "Do you trust the contents of this directory"} {
		if strings.Contains(screen, dialog) {
			t.Fatalf("the launched TUI shows %q:\n%s", dialog, screen)
		}
	}
	m.save("launch")
	// What the launcher did: the API key login (with the credential
	// placeholder, never the key) and the exact-path trust entry.
	sb := x.get(x.yolo)
	if got := x.exec(sb, 30*time.Second, true, "python3", "-c", `import json, os
d = json.load(open(os.path.expanduser("~/.codex/auth.json")))
print(str(d.get("OPENAI_API_KEY", "")).startswith("openshell:resolve:"))`); strings.TrimSpace(got.stdout) != "True" {
		t.Fatalf("~/.codex/auth.json does not hold the credential placeholder: %q", got.stdout)
	}
	if got := x.exec(sb, 30*time.Second, true, "grep", "-c", "-xF", `[projects."`+sb.Workdir+`"]`, "/sandbox/.codex/config.toml"); strings.TrimSpace(got.stdout) != "1" {
		t.Fatalf("~/.codex/config.toml does not trust %s exactly once: %q", sb.Workdir, got.stdout)
	}
}

// prompt types a prompt into the running TUI, waits for the scenario's
// closing line and records the hook events the turn produced.
func (x *tuiCodex) prompt(m *tmuxTerm, sandbox, text, done string, d time.Duration) (string, []hookRow) {
	x.t.Helper()
	since := time.Now()
	m.submit(text)
	screen := m.waitFor(d, done, func(s string) bool { return strings.Contains(s, done) })
	rows := x.waitRows(sandbox, since, "Stop")
	return screen, rows
}

func (x *tuiCodex) allowed() {
	t := x.t
	m := x.find("yolo")
	x.exec(x.get(x.yolo), 30*time.Second, true, "rm", "-f", allowedMarkerFile)
	_, rows := x.prompt(m, x.yolo, "Run the DCE2E-ALLOW scenario.", "DCE2E-TURN-DONE allow", 3*time.Minute)
	if got := x.exec(x.get(x.yolo), 30*time.Second, true, "cat", allowedMarkerFile); strings.TrimSpace(got.stdout) != "dce2e-allowed" {
		t.Fatalf("the allowed tool call left %q", got.stdout)
	}
	// The first turn opens the session; the notify bridge follows Stop.
	rows = x.waitRowsFor(x.yolo, rows, notifyEvent)
	x.record(modeTUI, "first turn", rows)
	for _, ev := range []string{"SessionStart", "UserPromptSubmit", "PreToolUse", "PostToolUse", "Stop", notifyEvent} {
		if countEvent(rows, ev) == 0 {
			t.Fatalf("no %s reached DefenseClaw for the first TUI turn: %v", ev, eventNames(rows))
		}
	}
	m.save("allowed")
}

func (x *tuiCodex) blocked() {
	t := x.t
	m := x.find("yolo")
	screen, rows := x.prompt(m, x.yolo, "Run the DCE2E-DENY scenario.", "DCE2E-TURN-DONE deny", 3*time.Minute)
	x.record(modeTUI, "blocked turn", rows)
	if !slices.ContainsFunc(rows, func(r hookRow) bool { return r.Event == "PreToolUse" && r.Action == "block" }) {
		t.Fatalf("DefenseClaw did not block the marker command: %v", rows)
	}
	if res := x.exec(x.get(x.yolo), 30*time.Second, true, "test", "-e", blockedMarkerFile); res.code == 0 {
		t.Fatalf("the blocked marker command ran: %s exists", blockedMarkerFile)
	}
	// The user sees DefenseClaw's reason in the transcript...
	if !strings.Contains(screen, "PreToolUse hook (blocked)") || !strings.Contains(screen, blockedReason) {
		t.Fatalf("the TUI does not show the block and its reason:\n%s", screen)
	}
	// ...and the model is told the same reason.
	if told := x.toldModel("E2E-SANDBOX-MARKER"); !strings.Contains(told, blockedReason) {
		t.Fatalf("the model's tool result for the denial = %q, want %q", told, blockedReason)
	}
	x.shown(modeTUI)
	m.save("blocked")
}

// noPrompt runs the command --safe asks about (a recursive delete of a
// scratch directory). Skip-permissions never asks: Codex, which cannot ask
// with approvals off, refuses rm -f style commands by itself, after
// DefenseClaw's PreToolUse allowed the call (so no PostToolUse follows).
func (x *tuiCodex) noPrompt() {
	t := x.t
	m := x.find("yolo")
	screen, rows := x.prompt(m, x.yolo, "Run the DCE2E-DANGER scenario.", "DCE2E-TURN-DONE danger", 3*time.Minute)
	x.record(modeTUI, "skip-permissions turn", rows)
	if strings.Contains(screen, approvalAsk) || countEvent(rows, "PermissionRequest") != 0 {
		t.Fatalf("the skip-permissions TUI asked for approval:\n%s", screen)
	}
	told := x.toldModel("rm -rf /tmp/dce2e-scratch-dir")
	if countEvent(rows, "PreToolUse") == 0 || !strings.Contains(told, "not permitted") {
		t.Fatalf("skip-permissions rm -rf: hooks %v, the model was told %q", eventNames(rows), told)
	}
	t.Logf("skip-permissions rm -rf: no prompt; Codex told the model %q", truncate(told, 200))
}

func (x *tuiCodex) subagent() {
	t := x.t
	m := x.find("yolo")
	since := time.Now()
	x.prompt(m, x.yolo, "Run the DCE2E-SUBAGENT scenario.", "DCE2E-TURN-DONE subagent", 3*time.Minute)
	rows := x.waitRows(x.yolo, since, "SubagentStart", "SubagentStop")
	x.record(modeTUI, "sub-agent turn", rows)
	m.save("subagent")
	if countEvent(rows, "SubagentStart") == 0 || countEvent(rows, "SubagentStop") == 0 {
		t.Fatalf("sub-agent hooks = %v", eventNames(rows))
	}
}

func (x *tuiCodex) compact() {
	m := x.find("yolo")
	since := time.Now()
	m.submit("/compact")
	m.waitFor(3*time.Minute, "the compaction", func(s string) bool { return strings.Contains(s, "Context compacted") })
	rows := x.waitRows(x.yolo, since, "PreCompact", "PostCompact")
	x.record(modeTUI, "/compact", rows)
	m.save("compact")
}

// tamper: while the TUI session is live, the sandbox's own Codex hook script
// posts a PostToolUse for a harmless marker call whose PreToolUse never
// reached DefenseClaw: what DefenseClaw sees when a hook dies and the tool
// runs anyway. The open pack alerts and keeps the sandbox running.
func (x *tuiCodex) tamper() {
	t := x.t
	sb := x.get(x.yolo)
	before := sb.Hooks
	var raw [8]byte
	if _, err := rand.Read(raw[:]); err != nil {
		t.Fatal(err)
	}
	id := "call_dce2e_tamper_" + hex.EncodeToString(raw[:])
	payload, err := json.Marshal(map[string]any{
		"session_id": "dce2e-tamper-" + hex.EncodeToString(raw[:4]), "turn_id": "dce2e-tamper-turn",
		"transcript_path": nil, "cwd": sb.Workdir, "hook_event_name": "PostToolUse", "model": "mock-model",
		"permission_mode": "bypassPermissions", "tool_name": "Bash", "tool_use_id": id,
		"tool_input":    map[string]any{"command": "echo DCE2E-TAMPER-MARKER"},
		"tool_response": "DCE2E-TAMPER-MARKER\n",
	})
	if err != nil {
		t.Fatal(err)
	}
	since := time.Now()
	// The payload travels as an argument: exec stdin must stay closed.
	script := `printf '%s' "$1" > /tmp/dce2e-tamper.json && "$2" --event PostToolUse --hook-contract "$3" < /tmp/dce2e-tamper.json`
	res := x.exec(sb, time.Minute, false, "sh", "-c", script, "sh", string(payload),
		path.Join(connector.SandboxHookDir, "codex-hook.sh"), sb.HookContract)
	if res.code != 0 {
		t.Fatalf("the PostToolUse hook exited %d: %s", res.code, truncate(res.stdout, 300))
	}
	ev := x.waitActivity(x.yolo, "hook_tamper on the feed", func(ev sandboxapi.ActivityEvent) bool {
		return ev.Kind == sandboxapi.ActivityFinding && ev.Reason == "hook_tamper" && !ev.Time.Before(since.Add(-time.Second))
	})
	after := x.waitHooks(x.yolo, func(h sandboxapi.HookCoverage) bool { return h.Tampered > before.Tampered })
	if ev.Severity != "HIGH" || !strings.Contains(ev.Message, "keeps running") || x.get(x.yolo).Phase != "ready" {
		t.Fatalf("hook_tamper event = %+v, want a HIGH alert that keeps the sandbox running", ev)
	}
	x.tamperHit = true
	// The TUI session is still usable afterwards.
	x.prompt(x.find("yolo"), x.yolo, "Say hello.", "DCE2E-TURN-DONE default", 2*time.Minute)
	t.Logf("hook tamper: %q (tampered %d → %d)", ev.Message, before.Tampered, after.Tampered)
}

// ctrlZ: Codex's TUI handles Ctrl-Z in the sandbox terminal; it neither
// suspends the session nor leaves the terminal hanging.
func (x *tuiCodex) ctrlZ() {
	m := x.find("yolo")
	m.keys("C-z")
	x.prompt(m, x.yolo, "Say hello.", "DCE2E-TURN-DONE default", 2*time.Minute)
	m.save("ctrl-z")
}

func (x *tuiCodex) exitUndo() {
	t := x.t
	m := x.find("yolo")
	x.prompt(m, x.yolo, "Run the DCE2E-EDIT scenario.", "DCE2E-TURN-DONE edit", 3*time.Minute)
	if edited, err := os.ReadFile(filepath.Join(x.project, "README.md")); err != nil || !strings.Contains(string(edited), "dce2e-edited-by-codex") {
		t.Fatalf("the edit did not reach the mounted project: %q, %v", edited, err)
	}
	since := time.Now()
	m.submit("/exit")
	screen := m.waitFor(3*time.Minute, "the end-of-session summary", func(s string) bool {
		return strings.Contains(s, "Session ended ·") && strings.Contains(s, "Keep changes?")
	})
	rows := x.waitRows(x.yolo, since, "SessionEnd")
	x.record(modeTUI, "/exit", rows)
	summary := lineWith(screen, "Session ended ·")
	if !strings.Contains(summary, "1 blocked") || !strings.Contains(summary, "1 file changed (+1 −0)") {
		t.Fatalf("summary line = %q", summary)
	}
	m.save("summary")
	m.keys("d", "Enter")
	m.waitFor(time.Minute, "the diff", func(s string) bool {
		return strings.Contains(s, "+dce2e-edited-by-codex") && strings.Count(s, "Keep changes?") >= 2
	})
	m.keys("u", "Enter")
	screen = m.waitFor(5*time.Minute, "the undo", func(s string) bool {
		return strings.Contains(s, "undone:") && strings.Contains(s, "Sandbox kept (stopped)") && m.atPrompt(s)
	})
	m.save("undo")
	if restored, err := os.ReadFile(filepath.Join(x.project, "README.md")); err != nil || string(restored) != x.readme {
		t.Fatalf("README after undo = %q, %v; want %q", restored, err, x.readme)
	}
	if got := x.get(x.yolo); got.Phase != "stopped" {
		t.Fatalf("phase after the session = %s, want stopped", got.Phase)
	}
	t.Logf("end of session: %s / %s", summary, lineWith(screen, "undone:"))
}

// ---- headless ------------------------------------------------------------------

// headless runs the same scenarios with `codex exec` through the launcher,
// as `sandbox run codex --prompt` does, in the same sandbox.
func (x *tuiCodex) headless() {
	t := x.t
	sb := x.start(x.yolo)
	run := func(label, prompt string, extra ...string) (string, []hookRow) {
		since := time.Now()
		argv, err := harness.Codex.LaunchArgv(harness.LaunchOptions{Mode: harness.Headless, Yolo: true, Prompt: prompt,
			Args: append(x.mockArgs(), extra...)})
		if err != nil {
			t.Fatal(err)
		}
		res, err := x.gw.Exec(x.ctx(5*time.Minute), sb.Name, argv, openshell.ExecOptions{WorkDir: sb.Workdir, Timeout: 3 * time.Minute})
		if err != nil {
			t.Fatalf("codex exec %q: %v", prompt, err)
		}
		out := string(res.Stdout) + string(res.Stderr)
		if res.ExitCode != 0 {
			t.Fatalf("codex exec %q exited %d: %s", prompt, res.ExitCode, truncate(out, 1500))
		}
		rows := x.waitRows(sb.Name, since, "SessionEnd")
		x.record(modeHeadless, label, rows)
		return out, rows
	}
	run("allowed", "Run the DCE2E-ALLOW scenario.")
	out, rows := run("blocked", "Run the DCE2E-DENY scenario.")
	if !slices.ContainsFunc(rows, func(r hookRow) bool { return r.Event == "PreToolUse" && r.Action == "block" }) ||
		!strings.Contains(out, "Command blocked by PreToolUse hook: "+blockedReason) {
		t.Fatalf("codex exec did not block the marker command with its reason: %v\n%s", eventNames(rows), truncate(out, 1500))
	}
	x.shown(modeHeadless)
	// The parent waits for its sub-agent: codex exec exits with the parent's
	// turn, and a sub-agent still running then never sends SubagentStop.
	if _, rows := run("sub-agent", "Run the DCE2E-SUBAGENT scenario."); countEvent(rows, "SubagentStart") == 0 || countEvent(rows, "SubagentStop") == 0 {
		t.Fatalf("codex exec sub-agent hooks = %v", eventNames(rows))
	}
	// A tiny auto-compaction limit compacts after the tool call.
	if _, rows := run("auto-compaction", "Run the DCE2E-ALLOW scenario.", "-c", "model_auto_compact_token_limit=5"); countEvent(rows, "PreCompact") == 0 || countEvent(rows, "PostCompact") == 0 {
		t.Fatalf("codex exec compaction hooks = %v", eventNames(rows))
	}
	x.stopLeftovers(sb)
}

// stopLeftovers kills Codex processes a timed-out exec left in the sandbox.
func (x *tuiCodex) stopLeftovers(sb *sandboxapi.Sandbox) {
	out := x.exec(sb, 30*time.Second, true, "ps", "-eo", "pid=,comm=").stdout
	var pids []string
	for _, line := range strings.Split(out, "\n") {
		if f := strings.Fields(line); len(f) == 2 && (f[1] == "codex" || f[1] == "node") {
			pids = append(pids, f[0])
		}
	}
	if len(pids) > 0 {
		x.t.Logf("killing leftover Codex processes %v", pids)
		x.exec(sb, 30*time.Second, false, append([]string{"kill"}, pids...)...)
	}
}

// dialogs shows what the launcher saves the user from: the same Codex
// without its login shows the sign-in screen, and in a folder it does not
// trust, the trust screen.
func (x *tuiCodex) dialogs() {
	sb := x.get(x.yolo)
	m := x.term("dialogs", nil)
	bin := filepath.Join(x.work, "bin", "defenseclaw-gateway")
	m.line(shellJoin(append([]string{bin, "sandbox", "exec", sb.Name, "--", "env", "HOME=/tmp/dce2e-fresh-home",
		"/usr/local/bin/codex", "--dangerously-bypass-approvals-and-sandbox"}, x.mockArgs()...)...))
	m.waitFor(2*time.Minute, "the sign-in screen", func(s string) bool {
		return strings.Contains(s, "Sign in with ChatGPT") && strings.Contains(s, "Provide your own API key")
	})
	m.save("no-login")
	m.keys("C-c")
	m.waitFor(time.Minute, "the shell", m.atPrompt)
	x.exec(sb, 30*time.Second, true, "mkdir", "-p", "/tmp/dce2e-untrusted")
	m.line(shellJoin(append([]string{bin, "sandbox", "exec", sb.Name, "--workdir", "/tmp/dce2e-untrusted", "--",
		harness.CodexLauncherPath, "--dangerously-bypass-approvals-and-sandbox"}, x.mockArgs()...)...))
	m.waitFor(2*time.Minute, "the trust screen", func(s string) bool {
		return strings.Contains(s, "Do you trust the contents of this directory?")
	})
	m.save("untrusted")
	m.keys("2", "Enter") // No, quit
	m.waitFor(time.Minute, "the shell", m.atPrompt)
}

// ---- --safe ----------------------------------------------------------------------

func (x *tuiCodex) safeRun() {
	t := x.t
	m := x.term("safe", nil)
	m.line(shellJoin(x.runArgs(x.safe, "--safe")...))
	screen := m.waitFor(20*time.Minute, "the --safe Codex TUI", func(s string) bool {
		return strings.Contains(s, codexBanner) && strings.Contains(s, "directory:") && strings.Contains(s, "› ")
	})
	if !strings.Contains(screen, "skip-permissions OFF (harness prompts kept)") || strings.Contains(screen, "YOLO mode") {
		t.Fatalf("--safe launch screen:\n%s", screen)
	}
	// Without Codex's own sandbox, --safe must ask before a harmless write
	// too (approval_policy untrusted), not only before a command Codex
	// deems dangerous.
	sb := x.get(x.safe)
	x.exec(sb, 30*time.Second, true, "rm", "-f", allowedMarkerFile)
	since := time.Now()
	m.submit("Run the DCE2E-ALLOW scenario.")
	screen = m.waitFor(3*time.Minute, "Codex's approval prompt", func(s string) bool { return strings.Contains(s, approvalAsk) })
	m.save("safe-ask")
	if !strings.Contains(screen, "dce2e-allowed") {
		t.Fatalf("the approval prompt does not show the marker command:\n%s", screen)
	}
	if x.exec(sb, 30*time.Second, true, "test", "-e", allowedMarkerFile).code == 0 {
		t.Fatal("the command ran before it was approved")
	}
	rows := x.waitRows(x.safe, since, "PermissionRequest")
	m.keys("y")
	m.waitFor(3*time.Minute, "the approved command", func(s string) bool { return strings.Contains(s, "DCE2E-TURN-DONE allow") })
	rows = x.waitRowsFor(x.safe, x.waitRows(x.safe, since, "Stop"), notifyEvent)
	x.record(modeTUI, "--safe turn", rows)
	if x.exec(sb, 30*time.Second, true, "test", "-e", allowedMarkerFile).code != 0 {
		t.Fatal("the approved command did not run")
	}
	// Ctrl-C at an idle prompt ends the session.
	since = time.Now()
	m.keys("C-c")
	screen = m.waitFor(3*time.Minute, "the end of the --safe session", func(s string) bool {
		return strings.Contains(s, "Session ended ·") && m.atPrompt(s)
	})
	x.record(modeTUI, "Ctrl-C", x.waitRows(x.safe, since, "SessionEnd"))
	m.save("safe-exit")
	if strings.Contains(screen, "Keep changes?") {
		t.Fatalf("a session without project changes asked to keep them:\n%s", screen)
	}

	// codex exec cannot show the prompt: PermissionRequest still reaches
	// DefenseClaw, and Codex refuses the command.
	sb = x.start(x.safe)
	x.exec(sb, 30*time.Second, true, "rm", "-f", allowedMarkerFile)
	since = time.Now()
	argv, err := harness.Codex.LaunchArgv(harness.LaunchOptions{Mode: harness.Headless, Prompt: "Run the DCE2E-ALLOW scenario.", Args: x.mockArgs()})
	if err != nil {
		t.Fatal(err)
	}
	res, err := x.gw.Exec(x.ctx(5*time.Minute), sb.Name, argv, openshell.ExecOptions{WorkDir: sb.Workdir, Timeout: 3 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	out := string(res.Stdout) + string(res.Stderr)
	rows = x.waitRows(sb.Name, since, "SessionEnd")
	x.record(modeHeadless, "--safe exec", rows)
	if countEvent(rows, "PermissionRequest") == 0 || !strings.Contains(out, "approval is not supported in exec mode") ||
		x.exec(sb, 30*time.Second, true, "test", "-e", allowedMarkerFile).code == 0 {
		t.Fatalf("--safe codex exec: %v\n%s", eventNames(rows), truncate(out, 1500))
	}
}

// ---- the shell wrapper -------------------------------------------------------------

func (x *tuiCodex) wrapper() {
	t := x.t
	rc := filepath.Join(x.work, "home", "wrapper-rc")
	x.ok(time.Minute, "enable", "codex", "--shell", "bash", "--rc", rc)
	m := x.term("wrapper", nil)
	m.line("source " + shellJoin(rc) + " && type codex | head -n 1")
	m.waitFor(time.Minute, "the wrapper function", func(s string) bool { return strings.Contains(s, "codex is a function") })
	m.line(shellJoin(append([]string{"codex"}, x.mockArgs()...)...))
	// The folder's most recent Codex sandbox is offered.
	m.waitFor(2*time.Minute, "the resume offer", func(s string) bool {
		return strings.Contains(s, "Sandbox "+x.safe+" (") && strings.Contains(s, "already holds this folder. Resume it?")
	})
	m.keys("y", "Enter")
	m.waitFor(10*time.Minute, "the wrapped Codex TUI", func(s string) bool {
		return strings.Contains(s, codexBanner) && strings.Contains(s, "› ")
	})
	screen, rows := x.prompt(m, x.safe, "Run the DCE2E-DENY scenario.", "DCE2E-TURN-DONE deny", 3*time.Minute)
	x.record(modeTUI, "wrapper turn", rows)
	if !strings.Contains(screen, "PreToolUse hook (blocked)") || countEvent(rows, "PreToolUse") == 0 {
		t.Fatalf("the wrapped session did not block the marker command:\n%s", screen)
	}
	since := time.Now()
	m.submit("/exit")
	m.waitFor(3*time.Minute, "the end of the wrapped session", func(s string) bool {
		return strings.Contains(s, "Session ended ·") && m.atPrompt(s)
	})
	x.record(modeTUI, "wrapper /exit", x.waitRows(x.safe, since, "SessionEnd"))
	m.save("wrapper")
	x.ok(time.Minute, "disable", "codex", "--shell", "bash", "--rc", rc)
	if data, _ := os.ReadFile(rc); strings.Contains(string(data), "sandbox run") {
		t.Fatalf("rc after disable:\n%s", data)
	}
}

// ---- Amazon Bedrock ----------------------------------------------------------------

// bedrockTUI runs one short real-model TUI session. Codex on Mantle's
// gpt-oss-20b loses its stream on the second turn of a conversation (headless
// `exec resume` too), so each prompt starts a new conversation with /new.
func (x *tuiCodex) bedrockTUI() {
	t := x.t
	key := os.Getenv("AWS_BEARER_TOKEN_BEDROCK")
	if key == "" {
		t.Skip("AWS_BEARER_TOKEN_BEDROCK is not set")
	}
	// A terminal server of its own carries the key in its environment,
	// never on a command line.
	m := x.term("bedrock", []string{"AWS_BEARER_TOKEN_BEDROCK=" + key})
	bin := filepath.Join(x.work, "bin", "defenseclaw-gateway")
	// No -m: the Mantle profile's default model.
	m.line(shellJoin(bin, "sandbox", "run", "codex", "--new", "--name", x.bedrock, "--llm", "bedrock",
		"--bedrock-region", envOr("AWS_REGION", "us-east-1")))
	screen := m.waitFor(20*time.Minute, "the Bedrock Codex TUI", func(s string) bool {
		return strings.Contains(s, codexBanner) && strings.Contains(s, harness.CodexMantleDefaultModel) && strings.Contains(s, "› ")
	})
	if !strings.Contains(screen, harness.CodexMantleDefaultModel+" (the default;") {
		t.Fatalf("the banner does not name the default model:\n%s", screen)
	}
	since := time.Now()
	m.submit("Use the shell tool to run exactly this command: echo dce2e-allowed > /tmp/dce2e-allowed.txt . Then reply with the single word done.")
	rows := x.waitRowsWithin(x.bedrock, since, 4*time.Minute, "PostToolUse", "Stop")
	m.submit("/new")
	since = time.Now()
	m.submit("Use the shell tool to run exactly this command: echo DCE2E-BLOCK-MARKER > /tmp/dce2e-blocked.txt . If it is blocked, reply with the word blocked and the reason.")
	screen = m.waitFor(4*time.Minute, "the real model's blocked call", func(s string) bool {
		return strings.Contains(s, "PreToolUse hook (blocked)")
	})
	rows = append(rows, x.waitRowsWithin(x.bedrock, since, 4*time.Minute, "Stop")...)
	x.record(modeTUI, "bedrock", rows)
	m.save("bedrock")
	if !strings.Contains(screen, blockedReason) {
		t.Fatalf("the Bedrock TUI does not show the block reason:\n%s", screen)
	}
	m.keys("C-c")
	m.waitFor(3*time.Minute, "the end of the Bedrock session", func(s string) bool {
		return strings.Contains(s, "Session ended ·") && m.atPrompt(s)
	})
	if res, err := x.api.Delete(x.ctx(5*time.Minute), x.bedrock, sandboxapi.DeleteRequest{}); err != nil || !res.Deleted {
		t.Fatalf("delete %s = %+v, %v", x.bedrock, res, err)
	}
}

// ---- matrix and teardown --------------------------------------------------------

func (x *tuiCodex) matrix() {
	t := x.t
	var b strings.Builder
	fmt.Fprintf(&b, "\n%-18s %-10s %-10s\n", "event", "headless", "tui")
	for _, ev := range codexEvents {
		fmt.Fprintf(&b, "%-18s %-10d %-10d\n", ev, x.seen[modeHeadless][ev], x.seen[modeTUI][ev])
	}
	fmt.Fprintf(&b, "blocked when denied (PreToolUse): headless %t, tui %t\n", x.seen[modeHeadless]["PreToolUse:block"] > 0, x.seen[modeTUI]["PreToolUse:block"] > 0)
	fmt.Fprintf(&b, "reason shown to user and model: headless %t, tui %t\n", x.blockedShown[modeHeadless], x.blockedShown[modeTUI])
	fmt.Fprintf(&b, "hook tamper during the TUI session: hook_tamper %t\n", x.tamperHit)
	fmt.Fprintf(&b, "binding token delivered in the environment (else as a provider placeholder): %t\n", x.tokenEnv)
	if len(x.unaudited) > 0 {
		keys := make([]string, 0, len(x.unaudited))
		for k, n := range x.unaudited {
			keys = append(keys, fmt.Sprintf("%s ×%d", k, n))
		}
		slices.Sort(keys)
		fmt.Fprintf(&b, "verdicts without a connector-hook audit row: %s\n", strings.Join(keys, ", "))
	}
	if len(x.sessionStartMissing) > 0 {
		fmt.Fprintf(&b, "sessions without a SessionStart verdict: %s\n", strings.Join(x.sessionStartMissing, ", "))
	}
	t.Log(b.String())
	if err := os.WriteFile(filepath.Join(x.work, "logs", "hook-matrix.txt"), []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	// Every registered event reaches DefenseClaw from the TUI; codex exec
	// has no /compact and no approval UI, but compacts and asks too.
	for _, ev := range codexEvents {
		if x.seen[modeTUI][ev] == 0 {
			t.Errorf("the TUI never sent %s", ev)
		}
		if x.seen[modeHeadless][ev] == 0 {
			t.Errorf("codex exec never sent %s", ev)
		}
	}
}

func (x *tuiCodex) deleteAll() {
	t := x.t
	for _, name := range []string{x.yolo, x.safe} {
		if res, err := x.api.Delete(x.ctx(5*time.Minute), name, sandboxapi.DeleteRequest{}); err != nil || !res.Deleted {
			t.Fatalf("delete %s = %+v, %v", name, res, err)
		}
	}
	waitFor(t, 3*time.Minute, "OpenShell to forget the sandboxes", func() error {
		for _, name := range []string{x.yolo, x.safe} {
			if _, err := x.gw.GetSandbox(x.ctx(20*time.Second), name); !openshell.IsNotFound(err) {
				return fmt.Errorf("%s: %v", name, err)
			}
		}
		return nil
	})
}

// ---- helpers ---------------------------------------------------------------------

// start starts a stopped sandbox and waits until it answers.
func (x *tuiCodex) start(name string) *sandboxapi.Sandbox {
	x.t.Helper()
	sb := x.get(name)
	if sb.Phase != "ready" {
		var err error
		if sb, err = x.api.Start(x.ctx(10*time.Minute), name, sandboxapi.StartRequest{}); err != nil {
			x.t.Fatalf("start %s: %v", name, err)
		}
	}
	x.exec(sb, 30*time.Second, true, "true")
	return sb
}

// record adds a step's hook rows to the matrix.
func (x *tuiCodex) record(mode, label string, rows []hookRow) {
	for _, r := range rows {
		x.seen[mode][r.Event]++
		if r.Action == "block" {
			x.seen[mode][r.Event+":block"]++
		}
		if r.Unaudited {
			if x.unaudited == nil {
				x.unaudited = map[string]int{}
			}
			x.unaudited[mode+" "+r.Event]++
		}
	}
	if (label == "first turn" || label == "allowed" || label == "--safe turn" || label == "--safe exec") && countEvent(rows, "SessionStart") == 0 {
		x.sessionStartMissing = append(x.sessionStartMissing, mode+" "+label)
	}
	x.t.Logf("%s %s: %s", mode, label, strings.Join(eventNames(rows), " "))
}

// shown notes that a mode showed the block reason to the user and the
// model.
func (x *tuiCodex) shown(mode string) {
	if x.blockedShown == nil {
		x.blockedShown = map[string]bool{}
	}
	x.blockedShown[mode] = true
}

// toldModel returns the last tool result the mock model received that
// contains want.
func (x *tuiCodex) toldModel(want string) string {
	f, err := os.Open(filepath.Join(x.work, "logs", "mock-openai.jsonl"))
	if err != nil {
		return ""
	}
	defer f.Close()
	var told string
	s := bufio.NewScanner(f)
	s.Buffer(make([]byte, 0, 64<<10), 4<<20)
	for s.Scan() {
		var rec struct {
			Summary struct {
				LastToolOutput string `json:"last_tool_output"`
			} `json:"summary"`
		}
		if json.Unmarshal(s.Bytes(), &rec) == nil && strings.Contains(rec.Summary.LastToolOutput, want) {
			told = rec.Summary.LastToolOutput
		}
	}
	return told
}

// hookRow is one hook verdict DefenseClaw recorded for a sandbox.
type hookRow struct {
	At     time.Time
	Event  string
	Action string
	Reason string
	// Unaudited marks a verdict (hook_decision) without its connector-hook
	// audit row.
	Unaudited bool
}

// rows reads the sandbox's hook verdicts at or after since from the
// daemon's audit log: the connector-hook rows (the notify bridge is audited
// as a synthetic Stop), plus the hook_decision records of verdicts whose
// connector-hook row is missing.
func (x *tuiCodex) rows(sandbox string, since time.Time) []hookRow {
	x.t.Helper()
	db, err := sql.Open("sqlite", "file:"+filepath.Join(x.work, "dc", "audit.db")+"?mode=ro")
	if err != nil {
		x.t.Fatal(err)
	}
	defer db.Close()
	q, err := db.QueryContext(x.ctx(30*time.Second),
		`SELECT timestamp, action, structured_json FROM audit_events WHERE action IN ('connector-hook', 'connector-hook-synthetic', 'hook_decision')`)
	if err != nil {
		x.t.Fatalf("read the audit log: %v", err)
	}
	defer q.Close()
	var audited, decisions []hookRow
	for q.Next() {
		var at, action string
		var structured sql.NullString
		if err := q.Scan(&at, &action, &structured); err != nil {
			x.t.Fatal(err)
		}
		ts, err := time.Parse(time.RFC3339Nano, at)
		if err != nil || ts.Before(since) {
			continue
		}
		if action == "hook_decision" {
			var doc map[string]any
			if json.Unmarshal([]byte(structured.String), &doc) != nil || doc["defenseclaw.sandbox.name"] != sandbox {
				continue
			}
			event, _ := doc["defenseclaw.hook.event"].(string)
			verdict, _ := doc["defenseclaw.guardrail.effective_action"].(string)
			// Stop also carries the notify bridge's verdicts; its
			// connector-hook rows are the record.
			if event != "" && event != "Stop" {
				decisions = append(decisions, hookRow{At: ts, Event: event, Action: verdict, Unaudited: true})
			}
			continue
		}
		var doc struct {
			Event  string            `json:"event"`
			Action string            `json:"action"`
			Reason string            `json:"reason"`
			Extra  map[string]string `json:"extra"`
		}
		if json.Unmarshal([]byte(structured.String), &doc) != nil || doc.Extra["sandbox_name"] != sandbox {
			continue
		}
		event := doc.Event
		if action == "connector-hook-synthetic" {
			event = notifyEvent
		}
		audited = append(audited, hookRow{At: ts, Event: event, Action: doc.Action, Reason: doc.Reason})
	}
	if err := q.Err(); err != nil {
		x.t.Fatal(err)
	}
	// A verdict is recorded just before its audit row; one with no audit
	// row of its event within two seconds after it lost that row.
	out := audited
	for _, d := range decisions {
		if !slices.ContainsFunc(audited, func(a hookRow) bool {
			return a.Event == d.Event && !a.At.Before(d.At) && a.At.Sub(d.At) < 2*time.Second
		}) {
			out = append(out, d)
		}
	}
	slices.SortFunc(out, func(a, b hookRow) int { return a.At.Compare(b.At) })
	return out
}

// waitRows waits until every event in want was audited for the sandbox since
// the given time and returns everything audited since then.
func (x *tuiCodex) waitRows(sandbox string, since time.Time, want ...string) []hookRow {
	x.t.Helper()
	return x.waitRowsWithin(sandbox, since, time.Minute, want...)
}

func (x *tuiCodex) waitRowsWithin(sandbox string, since time.Time, d time.Duration, want ...string) []hookRow {
	x.t.Helper()
	var rows []hookRow
	waitFor(x.t, d, strings.Join(want, ", ")+" from "+sandbox, func() error {
		rows = x.rows(sandbox, since)
		for _, ev := range want {
			if countEvent(rows, ev) == 0 {
				return fmt.Errorf("audited so far: %v", eventNames(rows))
			}
		}
		return nil
	})
	return rows
}

// waitRowsFor extends rows with a late event (the notify bridge runs after
// the turn).
func (x *tuiCodex) waitRowsFor(sandbox string, rows []hookRow, event string) []hookRow {
	x.t.Helper()
	if len(rows) == 0 || countEvent(rows, event) > 0 {
		return rows
	}
	return x.waitRows(sandbox, rows[0].At, event)
}

func countEvent(rows []hookRow, event string) int {
	n := 0
	for _, r := range rows {
		if r.Event == event {
			n++
		}
	}
	return n
}

func eventNames(rows []hookRow) []string {
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		name := r.Event
		if r.Action != "" && r.Action != "allow" {
			name += "(" + r.Action + ")"
		}
		if r.Unaudited {
			name += "[no audit row]"
		}
		out = append(out, name)
	}
	return out
}

func lineWith(screen, substr string) string {
	for _, l := range strings.Split(screen, "\n") {
		if strings.Contains(l, substr) {
			return strings.TrimSpace(l)
		}
	}
	return ""
}

func httpGet(url string) error {
	cmd := exec.Command("curl", "-fsS", "-o", "/dev/null", "--max-time", "5", url)
	return cmd.Run()
}

// ---- tmux ------------------------------------------------------------------------

// tmuxTerm is one shell in a detached tmux session on the test's private
// tmux server.
type tmuxTerm struct {
	x      *tuiCodex
	socket string
	name   string
}

var ansiRE = regexp.MustCompile(`\x1b\[[0-9;?]*[A-Za-z]`)

// term starts a 220x60 shell in the project folder. Sessions with extra
// environment get a tmux server of their own: a server keeps the
// environment of the client that started it.
func (x *tuiCodex) term(label string, extraEnv []string) *tmuxTerm {
	x.t.Helper()
	socket := x.prefix
	if len(extraEnv) > 0 {
		socket += "-" + label
	}
	m := &tmuxTerm{x: x, socket: socket, name: x.prefix + "-" + label}
	environ := append(append([]string{}, x.cliEnviron()...), "PS1="+shellPrompt+" ", "TERM=xterm-256color")
	cmd := exec.Command(x.tmux, "-L", socket, "new-session", "-d", "-s", m.name, "-x", "220", "-y", "60", "-c", x.project,
		"--", "bash", "--norc", "--noprofile", "-i")
	cmd.Env = append(environ, extraEnv...)
	if out, err := cmd.CombinedOutput(); err != nil {
		x.t.Fatalf("tmux new-session %s: %v: %s", m.name, err, out)
	}
	m.run("set-option", "-t", m.name, "history-limit", "20000")
	x.terms = append(x.terms, m)
	m.waitFor(30*time.Second, "the shell", m.atPrompt)
	return m
}

func (x *tuiCodex) find(label string) *tmuxTerm {
	for _, m := range x.terms {
		if m.name == x.prefix+"-"+label {
			return m
		}
	}
	x.t.Fatalf("no terminal %s", label)
	return nil
}

func (m *tmuxTerm) run(args ...string) string {
	m.x.t.Helper()
	out, err := exec.Command(m.x.tmux, append([]string{"-L", m.socket}, args...)...).CombinedOutput()
	if err != nil {
		m.x.t.Fatalf("tmux %s: %v: %s", strings.Join(args, " "), err, out)
	}
	return string(out)
}

// screen is the pane with its scrollback, wrapped lines joined.
func (m *tmuxTerm) screen() string {
	m.x.t.Helper()
	return ansiRE.ReplaceAllString(m.run("capture-pane", "-p", "-J", "-S", "-3000", "-t", m.name), "")
}

// waitFor polls the screen until ok accepts it.
func (m *tmuxTerm) waitFor(d time.Duration, what string, ok func(string) bool) string {
	m.x.t.Helper()
	deadline := time.Now().Add(d)
	for {
		s := m.screen()
		if ok(s) {
			return s
		}
		if time.Now().After(deadline) {
			m.save("timeout")
			m.x.t.Fatalf("timed out after %s waiting for %s; screen:\n%s", d, what, tail(s, 40))
		}
		time.Sleep(500 * time.Millisecond)
	}
}

// atPrompt reports whether the shell prompt is the last line.
func (m *tmuxTerm) atPrompt(s string) bool {
	lines := strings.Split(strings.TrimRight(s, "\n "), "\n")
	return strings.TrimSpace(lines[len(lines)-1]) == shellPrompt
}

// line types a command line into the shell.
func (m *tmuxTerm) line(text string) {
	m.run("send-keys", "-t", m.name, "-l", text)
	m.run("send-keys", "-t", m.name, "Enter")
}

// submit types text into the Codex composer, waits until the composer shows
// it and presses Enter.
func (m *tmuxTerm) submit(text string) {
	m.x.t.Helper()
	m.run("send-keys", "-t", m.name, "-l", text)
	m.waitFor(30*time.Second, "the composer to show "+strconv.Quote(text), func(s string) bool {
		return strings.Contains(lastLines(s, 8), "› "+text)
	})
	m.run("send-keys", "-t", m.name, "Enter")
}

func (m *tmuxTerm) keys(keys ...string) {
	for _, k := range keys {
		m.run("send-keys", "-t", m.name, k)
	}
}

// save keeps the screen under logs/screens as evidence.
func (m *tmuxTerm) save(label string) {
	m.x.screens++
	path := filepath.Join(m.x.work, "logs", "screens", fmt.Sprintf("%02d-%s-%s.txt", m.x.screens, strings.TrimPrefix(m.name, m.x.prefix+"-"), label))
	if err := os.WriteFile(path, []byte(m.screen()), 0o600); err != nil {
		m.x.t.Logf("save screen: %v", err)
	}
}

func (m *tmuxTerm) close() {
	_ = exec.Command(m.x.tmux, "-L", m.socket, "kill-session", "-t", m.name).Run()
	if out, err := exec.Command(m.x.tmux, "-L", m.socket, "list-sessions").CombinedOutput(); err != nil || len(strings.TrimSpace(string(out))) == 0 {
		_ = exec.Command(m.x.tmux, "-L", m.socket, "kill-server").Run()
	}
}

func lastLines(s string, n int) string {
	lines := strings.Split(strings.TrimRight(s, "\n "), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

func tail(s string, n int) string { return lastLines(s, n) }
