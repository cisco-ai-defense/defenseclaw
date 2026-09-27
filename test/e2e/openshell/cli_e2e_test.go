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
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/openshell/harness"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

// TestSandboxCLI drives the `defenseclaw-gateway sandbox` commands against
// the live daemon and OpenShell gateway, with the mock models standing in:
//
//   - doctor sees the daemon and the host;
//   - `run claude --detach` runs a prompt in the background; its hooks reach
//     the ingress, a DefenseClaw-blocked marker command is denied, the live
//     project edit is visible on the host and the masked .env is empty;
//   - egress: a blocklisted host is refused until `unblock --sandbox`;
//   - the nested-repository guard quarantines a .git created in the mount;
//   - review, undo (the project is restored), approvals, delete;
//   - `run codex --detach` with the mock Responses server: the marker
//     command is denied;
//   - the shell wrapper toggles in a scratch rc file, and teardown plans
//     (dry run only: the gateway is shared).
//
// Real models: DEFENSECLAW_E2E_BEDROCK=1 adds a Claude Code and a Codex run
// on Amazon Bedrock (AWS_BEARER_TOKEN_BEDROCK must hold a short-term key).
//
//	DEFENSECLAW_E2E_WORK_DIR=/data/dc-openshell/scratch/e2e DEFENSECLAW_E2E_PREFIX=f2b-e2e \
//	go test -tags openshell_integration ./test/e2e/openshell/ -run TestSandboxCLI -v -timeout 90m
func TestSandboxCLI(t *testing.T) {
	work := os.Getenv("DEFENSECLAW_E2E_WORK_DIR")
	if work == "" {
		t.Skip("set DEFENSECLAW_E2E_WORK_DIR to run the live sandbox CLI test")
	}
	e := &env{
		t: t, root: t, prefix: envOr("DEFENSECLAW_E2E_PREFIX", "dc-e2e") + "-cli",
		apiPort: envInt(t, "DEFENSECLAW_E2E_API_PORT", 28970) + 100,
		mock:    envInt(t, "DEFENSECLAW_E2E_MOCK_PORT", 28921) + 100,
	}
	e.repo = repoRoot(t)
	e.work = filepath.Join(work, e.prefix)
	c := &cliEnv{env: e, openaiPort: e.mock + 1}
	c.claude, c.codex = e.prefix+"-c", e.prefix+"-x"

	e.step("setup", func() { e.setup(); c.setupCLI() })
	e.step("start daemon", e.startDaemon)
	e.step("doctor", c.doctor)
	e.step("run claude detached", c.runClaude)
	e.step("blocked marker command", c.blockedCommand)
	e.step("egress block and unblock", c.egress)
	e.step("masked secret and live edit", c.liveEdit)
	e.step("nested repository guard", c.nestedRepo)
	e.step("review and undo", c.reviewUndo)
	e.step("approvals and policy", c.approvalsPolicy)
	e.step("delete claude", func() { c.delete(c.claude) })
	e.step("run codex detached", c.runCodex)
	e.step("delete codex", func() { c.delete(c.codex) })
	if os.Getenv("DEFENSECLAW_E2E_BEDROCK") == "1" {
		e.step("bedrock claude", c.bedrockClaude)
		e.step("bedrock codex", c.bedrockCodex)
	}
	e.step("shell wrapper", c.wrapper)
	e.step("teardown plan", c.teardownPlan)
}

type cliEnv struct {
	*env
	openaiPort    int
	claude, codex string
	environ       []string
}

func (c *cliEnv) setupCLI() {
	t := c.t
	// Both harnesses judge hooks with the rule pack (the marker rule).
	cfgPath := filepath.Join(c.work, "dc", "config.yaml")
	raw, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	cfg := strings.Replace(string(raw), "harnesses: [claudecode]", "harnesses: [claudecode, codex]", 1)
	writeFile(t, cfgPath, []byte(cfg), 0o600)

	mockLog := filepath.Join(c.work, "logs", "mock-openai.jsonl")
	px := c.spawn("mock-openai", "python3", filepath.Join(c.repo, "test", "e2e", "openshell", "mock_openai.py"),
		"--host", "127.0.0.1", "--port", strconv.Itoa(c.openaiPort), "--quiet", "--log", mockLog,
		"--script", filepath.Join(c.repo, "test", "e2e", "openshell", "scenarios", "daemon-codex.json"))
	c.root.Cleanup(func() { stop(px) })
	waitFor(t, 20*time.Second, "the mock Responses server", func() error {
		resp, err := http.Get("http://127.0.0.1:" + strconv.Itoa(c.openaiPort) + "/v1/models")
		if err == nil {
			resp.Body.Close()
		}
		return err
	})
	// The daemon stops before this cleanup runs (it was started later), so
	// leftovers go through the gateway; e.sweep then deletes the providers
	// named after the prefix.
	c.root.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		for _, name := range []string{c.claude, c.codex, c.prefix + "-bc", c.prefix + "-bx"} {
			if _, err := c.gw.GetSandbox(ctx, name); err != nil {
				continue
			}
			c.root.Logf("cleanup: deleting leftover sandbox %s", name)
			if _, err := c.gw.DeleteSandbox(ctx, name); err != nil {
				c.root.Logf("cleanup: delete sandbox %s: %v", name, err)
			} else if err := c.gw.WaitDeleted(ctx, name); err != nil {
				c.root.Logf("cleanup: wait for %s: %v", name, err)
			}
		}
	})
}

// cli runs `defenseclaw-gateway sandbox args...` in the project folder.
func (c *cliEnv) cli(timeout time.Duration, args ...string) (string, string, int) {
	c.t.Helper()
	if c.environ == nil {
		real, _ := os.UserHomeDir()
		xdg := os.Getenv("XDG_CONFIG_HOME")
		if xdg == "" {
			xdg = filepath.Join(real, ".config")
		}
		for _, kv := range os.Environ() {
			k, _, _ := strings.Cut(kv, "=")
			if strings.HasPrefix(k, "DEFENSECLAW_") || strings.HasPrefix(k, "OPENCLAW_") || k == "HOME" || k == "XDG_CONFIG_HOME" ||
				k == "ANTHROPIC_API_KEY" || k == "OPENAI_API_KEY" || k == "CODEX_API_KEY" || k == "CLAUDE_CODE_OAUTH_TOKEN" {
				continue
			}
			c.environ = append(c.environ, kv)
		}
		c.environ = append(c.environ, "HOME="+filepath.Join(c.work, "home"), "XDG_CONFIG_HOME="+xdg, "SHELL=/bin/bash",
			"DEFENSECLAW_HOME="+filepath.Join(c.work, "dc"), "DEFENSECLAW_GATEWAY_TOKEN="+c.token, "NO_COLOR=1",
			"OPENAI_API_KEY=dce2e-mock-key-not-a-secret", "ANTHROPIC_API_KEY=dce2e-mock-key-not-a-secret")
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, filepath.Join(c.work, "bin", "defenseclaw-gateway"), append([]string{"sandbox"}, args...)...)
	cmd.Dir = c.project
	cmd.Env = c.environ
	cmd.Stdin = nil
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	code := 0
	if err != nil {
		var exit *exec.ExitError
		if !errorsAs(err, &exit) {
			c.t.Fatalf("sandbox %s: %v", strings.Join(args, " "), err)
		}
		code = exit.ExitCode()
	}
	return stdout.String(), stderr.String(), code
}

func errorsAs(err error, target **exec.ExitError) bool {
	e, ok := err.(*exec.ExitError)
	if ok {
		*target = e
	}
	return ok
}

// ok runs a command that must succeed.
func (c *cliEnv) ok(timeout time.Duration, args ...string) string {
	c.t.Helper()
	out, errOut, code := c.cli(timeout, args...)
	if code != 0 {
		c.t.Fatalf("sandbox %s exited %d:\n%s\n%s", strings.Join(args, " "), code, truncate(out, 3000), truncate(errOut, 3000))
	}
	return out
}

func (c *cliEnv) doctor() {
	out, _, _ := c.cli(5*time.Minute, "doctor", "--output", "json")
	var rep struct {
		OK     bool `json:"ok"`
		Checks []struct {
			ID, Status, Detail string
		} `json:"checks"`
	}
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		c.t.Fatalf("doctor json: %v\n%s", err, truncate(out, 2000))
	}
	for _, ch := range rep.Checks {
		if ch.ID == "defenseclaw-daemon" && ch.Status != "pass" {
			c.t.Fatalf("doctor daemon check = %s: %s", ch.Status, ch.Detail)
		}
		if ch.Status == "fail" {
			c.t.Logf("doctor: %s failed: %s", ch.ID, ch.Detail)
		}
	}
	human, _, _ := c.cli(5*time.Minute, "doctor")
	c.t.Logf("doctor:\n%s", truncate(human, 3000))
}

// waitRun waits for the sandbox's detached run to exit and returns its
// status and log.
func (c *cliEnv) waitRun(name string, d time.Duration) (int, string) {
	c.t.Helper()
	var status string
	waitFor(c.t, d, "the detached run in "+name, func() error {
		out, _, code := c.cli(time.Minute, "exec", name, "--", "cat", "/sandbox/.defenseclaw/runs/latest.exit")
		if code != 0 {
			return fmt.Errorf("still running")
		}
		status = strings.TrimSpace(out)
		return nil
	})
	logs := c.ok(time.Minute, "logs", name, "--lines", "40")
	n, err := strconv.Atoi(status)
	if err != nil {
		c.t.Fatalf("run status %q", status)
	}
	return n, logs
}

func (c *cliEnv) status(name string) sandboxapi.Sandbox {
	c.t.Helper()
	var sb sandboxapi.Sandbox
	if err := json.Unmarshal([]byte(c.ok(time.Minute, "status", name, "--output", "json")), &sb); err != nil {
		c.t.Fatalf("status json: %v", err)
	}
	return sb
}

func (c *cliEnv) execOut(name string, argv ...string) (string, int) {
	c.t.Helper()
	out, _, code := c.cli(2*time.Minute, append([]string{"exec", name, "--"}, argv...)...)
	return out, code
}

// harness runs one headless prompt in the running sandbox through the
// in-image launcher, as a second session would.
func (c *cliEnv) harness(name, prompt string) {
	c.t.Helper()
	argv, err := harness.ClaudeCode.LaunchArgv(harness.LaunchOptions{Mode: harness.Headless, Yolo: true, Prompt: prompt})
	if err != nil {
		c.t.Fatal(err)
	}
	out, code := c.execOut(name, argv...)
	c.t.Logf("harness %q exited %d: %s", prompt, code, truncate(strings.TrimSpace(out), 300))
}

func (c *cliEnv) runClaude() {
	t := c.t
	started := time.Now()
	out := c.ok(45*time.Minute, "run", "claude", "--detach", "--name", c.claude, "--llm", "none",
		"--credential", "ANTHROPIC_API_KEY=host.openshell.internal:"+strconv.Itoa(c.mock),
		"--env", "ANTHROPIC_BASE_URL=http://host.openshell.internal:"+strconv.Itoa(c.mock),
		"--", "-p", "Write the allowed marker file.")
	t.Logf("run (%s):\n%s", time.Since(started).Round(time.Second), truncate(out, 3000))
	for _, want := range []string{"Sandbox " + c.claude + " · Claude Code · skip-permissions ON", "Hidden", ".env",
		"running in the background"} {
		if !strings.Contains(out, want) {
			t.Fatalf("run output lacks %q", want)
		}
	}
	code, logs := c.waitRun(c.claude, 5*time.Minute)
	if code != 0 {
		t.Fatalf("the detached harness exited %d:\n%s", code, logs)
	}
	if got, _ := c.execOut(c.claude, "cat", allowedMarkerFile); strings.TrimSpace(got) != "dce2e-allowed" {
		t.Fatalf("the allowed tool call left %q (logs: %s)", got, truncate(logs, 500))
	}
	waitFor(t, time.Minute, "hook traffic at the ingress", func() error {
		if h := c.status(c.claude).Hooks; h.ToolCalls == 0 {
			return fmt.Errorf("hooks %+v", h)
		}
		return nil
	})
	list := c.ok(time.Minute, "list")
	if !strings.Contains(list, c.claude) {
		t.Fatalf("list lacks %s:\n%s", c.claude, list)
	}
}

func (c *cliEnv) blockedCommand() {
	t := c.t
	before := c.status(c.claude).Hooks
	c.harness(c.claude, "Run the DCE2E-DENY scenario.")
	if _, code := c.execOut(c.claude, "test", "-e", blockedMarkerFile); code == 0 {
		t.Fatalf("the blocked marker command ran: %s exists", blockedMarkerFile)
	}
	waitFor(t, time.Minute, "the blocked tool call", func() error {
		if h := c.status(c.claude).Hooks; h.ToolBlocked <= before.ToolBlocked {
			return fmt.Errorf("hooks %+v", h)
		}
		return nil
	})
	var feed struct{ Events []sandboxapi.ActivityEvent }
	if err := json.Unmarshal([]byte(c.ok(time.Minute, "activity", "--sandbox", c.claude, "--output", "json")), &feed); err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(feed.Events, func(ev sandboxapi.ActivityEvent) bool { return ev.Kind == sandboxapi.ActivityToolBlocked }) {
		t.Fatalf("no tool.blocked in the activity feed (%d events)", len(feed.Events))
	}
}

func (c *cliEnv) proxyConnect(name, url string) string {
	script := `[ -n "$DEFENSECLAW_EGRESS_URL" ] || { echo no-proxy; exit 0; }; curl -sS -o /dev/null --max-time 20 -w '%{http_connect}' --proxy "$DEFENSECLAW_EGRESS_URL" '` + url + `' 2>/dev/null; true`
	out, _ := c.execOut(name, "sh", "-c", script)
	return strings.TrimSpace(out)
}

func (c *cliEnv) egress() {
	t := c.t
	if got := c.proxyConnect(c.claude, "https://"+allowedHost+"/"); got != "200" {
		t.Fatalf("%s through the proxy = %q", allowedHost, got)
	}
	if got := c.proxyConnect(c.claude, "https://"+blockedHost+"/dce2e"); got == "200" {
		t.Fatalf("%s went through before the unblock", blockedHost)
	}
	waitFor(t, time.Minute, "egress.blocked on the feed", func() error {
		out, _, _ := c.cli(time.Minute, "activity", "--sandbox", c.claude)
		if !strings.Contains(out, "✗ "+blockedHost) {
			return fmt.Errorf("feed:\n%s", truncate(out, 500))
		}
		return nil
	})
	out := c.ok(time.Minute, "unblock", blockedHost, "--sandbox", c.claude)
	if !strings.Contains(out, "unblocked "+blockedHost+" in "+c.claude) {
		t.Fatalf("unblock output: %s", out)
	}
	if got := c.proxyConnect(c.claude, "https://"+blockedHost+"/dce2e"); got != "200" {
		t.Fatalf("%s after the unblock = %q", blockedHost, got)
	}
}

func (c *cliEnv) liveEdit() {
	t := c.t
	if out, code := c.execOut(c.claude, "sh", "-c", "wc -c < .env"); code != 0 || strings.TrimSpace(out) != "0" {
		t.Fatalf("the masked .env inside the sandbox = %q (exit %d), want empty", out, code)
	}
	c.harness(c.claude, "Run the DCE2E-EDIT scenario.")
	edited, err := os.ReadFile(filepath.Join(c.project, "README.md"))
	if err != nil || !strings.Contains(string(edited), "dce2e-edited") {
		t.Fatalf("the live edit is not on the host: %q, %v", edited, err)
	}
}

// nestedRepo plants a .git directory and a .git file (a gitdir pointer, the
// form undo can see once it is quarantined) in the mounted project.
func (c *cliEnv) nestedRepo() {
	t := c.t
	if _, code := c.execOut(c.claude, "mkdir", "-p", "sub/nested/.git/objects"); code != 0 {
		t.Fatal("could not create the nested repository")
	}
	if _, code := c.execOut(c.claude, "sh", "-c", "mkdir -p sub/pointer && printf 'gitdir: /tmp/dce2e-gitdir\\n' > sub/pointer/.git"); code != 0 {
		t.Fatal("could not create the .git file")
	}
	for _, rel := range []string{"sub/nested", "sub/pointer"} {
		var quarantined string
		waitFor(t, time.Minute, rel+"/.git to be quarantined", func() error {
			if _, err := os.Lstat(filepath.Join(c.project, filepath.FromSlash(rel), ".git")); err == nil {
				return fmt.Errorf("%s/.git is still there", rel)
			}
			sb := c.status(c.claude)
			for _, n := range sb.NestedRepos {
				if n.Path == rel+"/.git" && n.Quarantined != "" {
					quarantined = n.Quarantined
					return nil
				}
			}
			return fmt.Errorf("nested repos %+v", sb.NestedRepos)
		})
		if _, err := os.Lstat(filepath.Join(c.project, filepath.FromSlash(quarantined))); err != nil {
			t.Fatalf("the quarantined entry %s is missing: %v", quarantined, err)
		}
		t.Logf("%s/.git quarantined as %s", rel, quarantined)
	}
	var feed struct{ Events []sandboxapi.ActivityEvent }
	if err := json.Unmarshal([]byte(c.ok(time.Minute, "activity", "--sandbox", c.claude, "--output", "json")), &feed); err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(feed.Events, func(ev sandboxapi.ActivityEvent) bool { return ev.Reason == sandboxapi.ReasonNestedRepo }) {
		t.Fatal("no nested-repository finding on the activity feed")
	}
}

func (c *cliEnv) reviewUndo() {
	t := c.t
	rev := c.ok(2*time.Minute, "review", c.claude)
	if !strings.Contains(rev, "changed") {
		t.Fatalf("review:\n%s", rev)
	}
	t.Logf("review:\n%s", truncate(rev, 2000))
	out := c.ok(5*time.Minute, "undo", c.claude, "--yes")
	t.Logf("undo:\n%s", truncate(out, 2000))
	restored, err := os.ReadFile(filepath.Join(c.project, "README.md"))
	if err != nil || string(restored) != c.readme {
		t.Fatalf("README after undo = %q, %v", restored, err)
	}
	// Undo removes the quarantined .git file (content git tracks); the
	// quarantined directory held only an empty folder, which git cannot see.
	var left []string
	_ = filepath.WalkDir(filepath.Join(c.project, "sub"), func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			left = append(left, p)
		}
		return nil
	})
	if len(left) > 0 {
		t.Fatalf("undo left files of the planted repositories: %v", left)
	}
	if sb := c.status(c.claude); sb.Phase != "stopped" {
		t.Fatalf("phase after undo = %s", sb.Phase)
	}
}

func (c *cliEnv) approvalsPolicy() {
	t := c.t
	var list struct{ Approvals []sandboxapi.Approval }
	if err := json.Unmarshal([]byte(c.ok(time.Minute, "approvals", "--output", "json")), &list); err != nil {
		t.Fatal(err)
	}
	explain := c.ok(time.Minute, "policy", "explain", "--harness", "claude")
	if !strings.Contains(explain, "SETTING") || !strings.Contains(explain, "profile") {
		t.Fatalf("policy explain:\n%s", explain)
	}
	packs := c.ok(time.Minute, "pack", "list")
	if !strings.Contains(packs, "sha256:") {
		t.Fatalf("pack list:\n%s", packs)
	}
}

func (c *cliEnv) delete(name string) {
	t := c.t
	c.ok(5*time.Minute, "delete", name, "--yes")
	waitFor(t, 3*time.Minute, "OpenShell to forget "+name, func() error {
		out, _, _ := c.cli(time.Minute, "list", "--output", "json")
		if strings.Contains(out, `"name": "`+name+`"`) {
			return fmt.Errorf("still listed")
		}
		return nil
	})
}

func (c *cliEnv) codexMockArgs() []string {
	base := "http://host.openshell.internal:" + strconv.Itoa(c.openaiPort) + "/v1"
	return []string{"-c", `model_provider="mock"`, "-c", `model_providers.mock.name="mock"`,
		"-c", `model_providers.mock.base_url="` + base + `"`, "-c", `model_providers.mock.env_key="OPENAI_API_KEY"`,
		"-c", `model_providers.mock.wire_api="responses"`,
		// Codex sends a known model's tools in an input item the mock does
		// not read; an unknown model gets the classic tools field.
		"-m", "mock-model"}
}

func (c *cliEnv) runCodex() {
	t := c.t
	args := []string{"run", "codex", "--detach", "--new", "--name", c.codex, "--llm", "none",
		"--credential", "OPENAI_API_KEY=host.openshell.internal:" + strconv.Itoa(c.openaiPort),
		"--prompt", "Run the DCE2E-DENY scenario.", "--"}
	started := time.Now()
	out := c.ok(45*time.Minute, append(args, c.codexMockArgs()...)...)
	t.Logf("run codex (%s):\n%s", time.Since(started).Round(time.Second), truncate(out, 2000))
	code, logs := c.waitRun(c.codex, 5*time.Minute)
	t.Logf("codex exited %d:\n%s", code, truncate(logs, 1500))
	if _, rc := c.execOut(c.codex, "test", "-e", blockedMarkerFile); rc == 0 {
		t.Fatalf("Codex ran the blocked marker command")
	}
	waitFor(t, time.Minute, "the blocked Codex tool call", func() error {
		if h := c.status(c.codex).Hooks; h.ToolBlocked == 0 {
			return fmt.Errorf("hooks %+v", h)
		}
		return nil
	})
}

func (c *cliEnv) bedrockClaude() {
	t := c.t
	if os.Getenv("AWS_BEARER_TOKEN_BEDROCK") == "" {
		t.Skip("AWS_BEARER_TOKEN_BEDROCK is not set")
	}
	c.environ = append(c.environ, "AWS_BEARER_TOKEN_BEDROCK="+os.Getenv("AWS_BEARER_TOKEN_BEDROCK"))
	name := c.prefix + "-bc"
	c.ok(45*time.Minute, "run", "claude", "--detach", "--new", "--name", name, "--llm", "bedrock", "--bedrock-region", envOr("AWS_REGION", "us-east-1"),
		"--prompt", "Run `echo dce2e-allowed > /tmp/dce2e-allowed.txt` with the Bash tool, then say done.", "--", "--model", "anthropic.claude-haiku-4-5")
	code, logs := c.waitRun(name, 8*time.Minute)
	t.Logf("bedrock claude exited %d:\n%s", code, truncate(logs, 1500))
	if code != 0 || c.status(name).Hooks.ToolCalls == 0 {
		t.Fatalf("the real-model Claude Code run did not make a hooked tool call")
	}
	c.delete(name)
}

func (c *cliEnv) bedrockCodex() {
	t := c.t
	if os.Getenv("AWS_BEARER_TOKEN_BEDROCK") == "" {
		t.Skip("AWS_BEARER_TOKEN_BEDROCK is not set")
	}
	name := c.prefix + "-bx"
	c.ok(45*time.Minute, "run", "codex", "--detach", "--new", "--name", name, "--llm", "bedrock", "--bedrock-region", envOr("AWS_REGION", "us-east-1"),
		"--prompt", "Run `echo dce2e-allowed > /tmp/dce2e-allowed.txt` in the shell, then say done.", "--", "-m", "openai.gpt-oss-20b")
	code, logs := c.waitRun(name, 8*time.Minute)
	t.Logf("bedrock codex exited %d:\n%s", code, truncate(logs, 1500))
	if code != 0 || c.status(name).Hooks.ToolCalls == 0 {
		t.Fatalf("the real-model Codex run did not make a hooked tool call")
	}
	c.delete(name)
}

func (c *cliEnv) wrapper() {
	t := c.t
	rc := filepath.Join(c.work, "home", "wrapper-rc")
	c.ok(time.Minute, "enable", "claude", "--shell", "bash", "--rc", rc)
	data, err := os.ReadFile(rc)
	if err != nil || !strings.Contains(string(data), "sandbox run claude") {
		t.Fatalf("rc after enable: %q, %v", data, err)
	}
	out, err := exec.Command("bash", "--norc", "-c", `. "$1"; type claude`, "x", rc).CombinedOutput()
	if err != nil || !strings.Contains(string(out), "claude is a function") {
		t.Fatalf("type claude: %s, %v", out, err)
	}
	c.ok(time.Minute, "disable", "claude", "--shell", "bash", "--rc", rc)
	if data, _ := os.ReadFile(rc); strings.Contains(string(data), "sandbox run") {
		t.Fatalf("rc after disable:\n%s", data)
	}
}

func (c *cliEnv) teardownPlan() {
	out := c.ok(5*time.Minute, "teardown", "--dry-run", "--keep-images")
	c.t.Logf("teardown plan:\n%s", truncate(out, 2000))
	if !strings.Contains(out, "Sandbox teardown") {
		c.t.Fatalf("teardown dry run:\n%s", out)
	}
}
