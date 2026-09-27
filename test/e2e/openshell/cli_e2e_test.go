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
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/harness"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxcli"
)

// TestSandboxCLI drives the `defenseclaw-gateway sandbox` commands against
// the live daemon and OpenShell gateway, with the mock models standing in:
//
//   - doctor sees the daemon and the host;
//   - `run claude --detach` runs a prompt in the background; its hooks reach
//     the ingress, a DefenseClaw-blocked marker command is denied, the live
//     project edit is visible on the host and the masked .env is empty;
//   - egress: a blocklisted host is refused until `unblock --sandbox`;
//   - `sandbox exec` commands get the egress proxy and the harness shim;
//   - the nested-repository guard quarantines a .git created in the mount;
//   - review, undo (the project is restored), approvals, delete;
//   - `run codex --detach` with the mock Responses server: the marker
//     command is denied, and a tool call's plain curl reaches the allowed
//     host through the proxy Codex's launcher exports;
//   - copy mode (`--copy`) with a git project: the run uploads before it
//     probes, the agent's edit stays in the copy, held-back secrets are not
//     in it, and `pull --branch`, `--patch-out` and `--apply` (a conflict
//     first, which falls back to a branch and a patch) bring it back; then
//     `connect --refresh` resumes the stopped sandbox with a fresh copy;
//   - copy mode with a plain folder: the hidden git dir stays outside the
//     folder, `pull --branch` is refused and `--apply` lands the edit;
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

		tokenDelivery: e2eTokenDelivery(t),
	}
	e.repo = repoRoot(t)
	e.work = filepath.Join(work, e.prefix)
	c := &cliEnv{env: e, openaiPort: e.mock + 1}
	c.claude, c.codex = e.prefix+"-c", e.prefix+"-x"
	c.copyGit, c.copyPlain = e.prefix+"-cg", e.prefix+"-cp"

	e.step("setup", func() { e.setup(); c.setupCLI() })
	e.step("start daemon", e.startDaemon)
	e.step("doctor", c.doctor)
	e.step("run claude detached", c.runClaude)
	e.step("blocked marker command", c.blockedCommand)
	e.step("egress block and unblock", c.egress)
	e.step("exec gets the egress proxy", c.execProxy)
	e.step("terminal attach", c.terminalAttach)
	e.step("masked secret and live edit", c.liveEdit)
	e.step("nested repository guard", c.nestedRepo)
	e.step("review and undo", c.reviewUndo)
	e.step("approvals and policy", c.approvalsPolicy)
	e.step("delete claude", func() { c.delete(c.claude) })
	e.step("run codex detached", c.runCodex)
	e.step("delete codex", func() { c.delete(c.codex) })
	e.step("detached run lifecycle under a generated name", c.detachedLifecycle)
	e.step("copy mode: git project run", c.copyGitRun)
	e.step("copy mode: pull back", c.copyGitPull)
	e.step("copy mode: resume with refresh", c.copyGitRefresh)
	e.step("delete copy-mode git sandbox", func() { c.delete(c.copyGit) })
	e.step("copy mode: plain folder", c.copyPlainRun)
	e.step("delete copy-mode plain sandbox", func() { c.delete(c.copyPlain) })
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
	// The copy-mode sandboxes and their projects: a git repository and a
	// plain folder, each with a held-back secret.
	copyGit, copyPlain         string
	copyGitProj, copyPlainProj string
	// generated are the sandboxes a run named itself.
	generated []string
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
	// The copy-mode projects: a git repository and a plain folder (no
	// repository anywhere above it), each with a secret-looking file the
	// copy must hold back.
	c.copyGitProj = filepath.Join(c.work, "proj", c.prefix+"-copy")
	c.copyPlainProj = filepath.Join(c.work, "proj", c.prefix+"-plain")
	for _, dir := range []string{c.copyGitProj, c.copyPlainProj} {
		writeFile(t, filepath.Join(dir, "README.md"), []byte(c.readme), 0o644)
		writeFile(t, filepath.Join(dir, ".env"), []byte("DCE2E_PLACEHOLDER=not-a-secret\n"), 0o600)
	}
	writeFile(t, filepath.Join(c.copyGitProj, "src", "app.txt"), []byte("app\n"), 0o644)
	c.gitIn(c.copyGitProj, "init", "-q", "-b", "main")
	c.gitIn(c.copyGitProj, "add", "README.md", "src/app.txt")
	c.gitIn(c.copyGitProj, "commit", "-q", "-m", "initial")

	// The daemon stops before this cleanup runs (it was started later), so
	// leftovers go through the gateway; e.sweep then deletes the providers
	// named after the prefix.
	c.root.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		for _, name := range append([]string{c.claude, c.codex, c.copyGit, c.copyPlain, c.prefix + "-bc", c.prefix + "-bx"}, c.generated...) {
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
	return c.cliIn(c.project, timeout, args...)
}

// cliIn runs `defenseclaw-gateway sandbox args...` in dir.
func (c *cliEnv) cliIn(dir string, timeout time.Duration, args ...string) (string, string, int) {
	c.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, filepath.Join(c.work, "bin", "defenseclaw-gateway"), append([]string{"sandbox"}, args...)...)
	cmd.Dir = dir
	cmd.Env = c.cliEnviron()
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

// cliEnviron is the environment the sandbox commands run with: the test's
// home and data directory, the daemon token, and harmless mock model keys
// in place of the user's.
func (c *cliEnv) cliEnviron() []string {
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
	return c.environ
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
	return c.okIn(c.project, timeout, args...)
}

// okIn runs a command in dir that must succeed.
func (c *cliEnv) okIn(dir string, timeout time.Duration, args ...string) string {
	c.t.Helper()
	out, errOut, code := c.cliIn(dir, timeout, args...)
	if code != 0 {
		c.t.Fatalf("sandbox %s exited %d:\n%s\n%s", strings.Join(args, " "), code, truncate(out, 3000), truncate(errOut, 3000))
	}
	return out
}

// gitIn runs a fixture git command in dir and returns its output.
func (c *cliEnv) gitIn(dir string, args ...string) string {
	c.t.Helper()
	cmd := exec.Command("git", append([]string{"-c", "user.name=dce2e", "-c", "user.email=dce2e@example.invalid"}, args...)...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		c.t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, truncate(string(out), 1000))
	}
	return string(out)
}

func (c *cliEnv) readFile(path string) string {
	c.t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		c.t.Fatal(err)
	}
	return string(data)
}

func wantAll(t *testing.T, what, got string, want ...string) {
	t.Helper()
	for _, w := range want {
		if !strings.Contains(got, w) {
			t.Fatalf("%s lacks %q:\n%s", what, w, truncate(got, 3000))
		}
	}
}

func (c *cliEnv) doctor() {
	out, errOut, code := c.cli(5*time.Minute, "doctor", "--output", "json")
	var rep struct {
		OK     bool `json:"ok"`
		Checks []struct {
			ID, Status, Detail string
		} `json:"checks"`
	}
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		c.t.Fatalf("doctor json (exit %d): %v\nstdout:\n%s\nstderr:\n%s", code, err, truncate(out, 2000), truncate(errOut, 2000))
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

// execProxy: a `sandbox exec` command runs through the image's sandbox-env
// wrapper, so it has the egress proxy settings (a plain curl reaches the
// allowed host through the proxy) and `claude` is the shim that starts the
// launcher.
func (c *cliEnv) execProxy() {
	t := c.t
	out, code := c.execOut(c.claude, "sh", "-c", `printf '%s %s ' "${HTTPS_PROXY:+proxy}" "$(command -v claude)"; `+
		`curl -sS -o /dev/null --max-time 20 -w '%{http_code}' 'https://`+allowedHost+`/' 2>/dev/null; true`)
	got := strings.Fields(out)
	t.Logf("sandbox exec: %v (exit %d)", got, code)
	if code != 0 || len(got) != 3 || got[0] != "proxy" || got[1] != harness.ClaudeCode.ShimPath() || got[2] != "200" {
		t.Fatalf("sandbox exec: proxy, harness command, curl = %v (exit %d), want proxy %s 200", got, code, harness.ClaudeCode.ShimPath())
	}
}

// terminalAttach runs `sandbox exec --tty` under script(1), so the command
// takes the foreground-terminal path `run` and `connect` use: a pseudo
// terminal inside the sandbox and the child's exit status back.
func (c *cliEnv) terminalAttach() {
	t := c.t
	script, err := exec.LookPath("script")
	if err != nil || runtime.GOOS != "linux" {
		t.Skip("util-linux script(1) is needed to give the CLI a terminal")
	}
	bin := filepath.Join(c.work, "bin", "defenseclaw-gateway")
	inner := shellJoin(bin, "sandbox", "exec", c.claude, "--", "sh", "-c", "test -t 0 && test -t 1 && echo DCE2E-TTY-OK; exit 3")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, script, "-q", "-e", "-f", "-c", inner, "/dev/null")
	cmd.Dir, cmd.Env = c.project, c.cliEnviron()
	out, err := cmd.CombinedOutput()
	var exit *exec.ExitError
	if !errorsAs(err, &exit) || exit.ExitCode() != 3 || !strings.Contains(string(out), "DCE2E-TTY-OK") {
		t.Fatalf("exec on a terminal = %v:\n%s", err, truncate(string(out), 1000))
	}
}

func shellJoin(args ...string) string {
	quoted := make([]string, len(args))
	for i, a := range args {
		quoted[i] = "'" + strings.ReplaceAll(a, "'", `'\''`) + "'"
	}
	return strings.Join(quoted, " ")
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
	// The guard may rename .git before mkdir -p creates objects/ in it; the
	// failed mkdir is the guard winning the race.
	if _, code := c.execOut(c.claude, "sh", "-c", "mkdir -p sub/nested/.git/objects || true"); code != 0 {
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
	// Files git never sees that run on the host: a package bin entry and an
	// executable in a Python bytecode cache, each hidden by the .gitignore
	// its directory carries (as `python -m venv` writes one).
	plant := "mkdir -p node_modules/.bin calc/__pycache__ && echo '*' > node_modules/.gitignore && echo '*' > calc/__pycache__/.gitignore" +
		" && printf '#!/bin/sh\\necho dce2e\\n' > node_modules/.bin/dce2e-tool && cp node_modules/.bin/dce2e-tool calc/__pycache__/dce2e.sh" +
		" && chmod +x node_modules/.bin/dce2e-tool calc/__pycache__/dce2e.sh"
	if out, code := c.execOut(c.claude, "sh", "-c", plant); code != 0 {
		t.Fatalf("could not write the ignored files (exit %d): %s", code, out)
	}
	rev := c.ok(2*time.Minute, "review", c.claude)
	if !strings.Contains(rev, "changed") {
		t.Fatalf("review:\n%s", rev)
	}
	t.Logf("review:\n%s", truncate(rev, 2000))
	wantAll(t, "review", rev, "node_modules/", "Undo cannot restore node_modules/", "calc/__pycache__/dce2e.sh")
	out := c.ok(5*time.Minute, "undo", c.claude, "--yes")
	t.Logf("undo:\n%s", truncate(out, 2000))
	wantAll(t, "undo", out, "remove  2 files the session wrote to calc/__pycache__/", "undo cannot restore node_modules/")
	restored, err := os.ReadFile(filepath.Join(c.project, "README.md"))
	if err != nil || string(restored) != c.readme {
		t.Fatalf("README after undo = %q, %v", restored, err)
	}
	if _, err := os.Lstat(filepath.Join(c.project, "calc", "__pycache__")); !os.IsNotExist(err) {
		t.Fatalf("undo left the bytecode cache the session wrote: %v", err)
	}
	// What undo cannot restore is left, named in its output; remove it.
	if _, err := os.Lstat(filepath.Join(c.project, "node_modules", ".bin", "dce2e-tool")); err != nil {
		t.Fatalf("node_modules changed under undo: %v", err)
	}
	if err := os.RemoveAll(filepath.Join(c.project, "node_modules")); err != nil {
		t.Fatal(err)
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
	// The table and the constraints fit 120 columns; only warnings, which
	// are sentences, may wrap.
	for _, line := range strings.Split(explain, "\n") {
		if n := len([]rune(line)); n > 120 && !strings.HasPrefix(line, "  ⚠") {
			t.Fatalf("policy explain line of %d characters:\n%s", n, truncate(line, 300))
		}
	}
	// Keys longer than the old 14-character column no longer run into
	// their values.
	if show := c.ok(time.Minute, "policy", "show", "--harness", "claude"); !regexp.MustCompile(`(?m)^  hooks\.fail_mode +\S`).MatchString(show) {
		t.Fatalf("policy show:\n%s", show)
	}
	packs := c.ok(time.Minute, "pack", "list")
	if !strings.Contains(packs, "sha256:") {
		t.Fatalf("pack list:\n%s", packs)
	}
}

func (c *cliEnv) delete(name string) {
	t := c.t
	// The --credential profiles the sandbox's providers use go with it
	// once nothing else uses them.
	var credProfiles []string
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if list, err := c.gw.ListProviders(ctx); err == nil {
		for _, p := range list {
			if strings.HasPrefix(p.Name, name+"-cred-") && strings.HasPrefix(p.Type, "dc-cred-") {
				credProfiles = append(credProfiles, p.Type)
			}
		}
	}
	c.ok(5*time.Minute, "delete", name, "--yes")
	waitFor(t, 3*time.Minute, "OpenShell to forget "+name, func() error {
		out, _, _ := c.cli(time.Minute, "list", "--output", "json")
		if strings.Contains(out, `"name": "`+name+`"`) {
			return fmt.Errorf("still listed")
		}
		return nil
	})
	// Nothing of it is left in the data dir.
	if _, err := os.Lstat(filepath.Join(c.work, "dc", "sandboxes", name)); !os.IsNotExist(err) {
		t.Fatalf("delete left %s's data directory: %v", name, err)
	}
	for _, id := range credProfiles {
		if _, err := c.gw.GetProfile(ctx, id); !openshell.IsNotFound(err) {
			t.Fatalf("delete left the credential profile %s of %s: %v", id, name, err)
		}
	}
}

// detachedLifecycle starts a detached Claude Code run without --name (the
// name the run picks fits OpenShell's 19 characters) that works for a few
// minutes, and while it is going:
//   - a run with an --host-port DefenseClaw never opens fails before a
//     sandbox exists;
//   - a copy-mode run under the same name is refused before anything is
//     staged, with the way to resume it;
//   - a headless `connect --prompt` session in the sandbox leaves the
//     sandbox and the run going;
//   - `stop` says it ends the run, marks it interrupted and keeps its log,
//     which `logs` shows once the sandbox is stopped and after a restart.
func (c *cliEnv) detachedLifecycle() {
	t := c.t
	dir := filepath.Join(c.work, "proj", c.prefix+"-gen")
	writeFile(t, filepath.Join(dir, "README.md"), []byte(c.readme), 0o644)
	c.gitIn(dir, "init", "-q", "-b", "main")
	c.gitIn(dir, "add", "README.md")
	c.gitIn(dir, "commit", "-q", "-m", "initial")
	mock := []string{"--llm", "none", "--credential", "ANTHROPIC_API_KEY=host.openshell.internal:" + strconv.Itoa(c.mock),
		"--env", "ANTHROPIC_BASE_URL=http://host.openshell.internal:" + strconv.Itoa(c.mock)}
	out := c.okIn(dir, 45*time.Minute, append(append([]string{"run", "claude", "--detach"}, mock...), "--", "-p", "Run the DCE2E-SLOW scenario.")...)
	m := regexp.MustCompile(`Sandbox (\S+) · Claude Code`).FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("no sandbox name in the run's output:\n%s", truncate(out, 3000))
	}
	name := m[1]
	c.generated = append(c.generated, name)
	t.Logf("the run named its sandbox %s", name)
	if !openshell.ValidNewSandboxName(name) {
		t.Fatalf("generated name %q is not one OpenShell creates (at most %d characters)", name, openshell.MaxSandboxNameLen)
	}
	waitFor(t, 5*time.Minute, "the slow tool call in the streamed log", func() error {
		logs, _, _ := c.cliIn(dir, time.Minute, "logs", name)
		if !strings.Contains(logs, "→ Bash: sleep 200") || !strings.Contains(logs, "the run is still going") {
			return fmt.Errorf("logs:\n%s", truncate(logs, 800))
		}
		return nil
	})

	// A --host-port DefenseClaw never opens (its own hook ingress) fails
	// before anything is created, like the same port in a --credential.
	var st sandboxapi.Status
	if err := json.Unmarshal([]byte(c.ok(time.Minute, "status", "--output", "json")), &st); err != nil {
		t.Fatalf("status json: %v", err)
	}
	_, ingressPort, err := net.SplitHostPort(st.IngressAddr)
	if err != nil {
		t.Fatalf("ingress address %q: %v", st.IngressAddr, err)
	}
	_, errOut, code := c.cliIn(dir, 5*time.Minute, append(append([]string{"run", "claude", "--new", "--detach", "--host-port", ingressPort}, mock...), "--", "-p", "x")...)
	if code == 0 || !strings.Contains(errOut, "--host-port "+ingressPort+": DefenseClaw never opens DefenseClaw's sandbox hook ingress") {
		t.Fatalf("run --host-port %s exited %d:\n%s", ingressPort, code, truncate(errOut, 1000))
	}
	var listed struct{ Sandboxes []sandboxapi.Sandbox }
	if err := json.Unmarshal([]byte(c.ok(time.Minute, "list", "--output", "json")), &listed); err != nil {
		t.Fatalf("list json: %v", err)
	}
	for _, sb := range listed.Sandboxes {
		if sb.Name != name && sb.Project == dir {
			t.Fatalf("the refused --host-port run created %s", sb.Name)
		}
	}

	_, errOut, code = c.cliIn(dir, 5*time.Minute, append(append([]string{"run", "claude", "--copy", "--name", name, "--detach"}, mock...), "--", "-p", "x")...)
	if code == 0 || !strings.Contains(errOut, "a sandbox named "+name+" already exists") || !strings.Contains(errOut, "connect "+name+" --prompt TEXT") {
		t.Fatalf("run --copy --name %s exited %d:\n%s", name, code, truncate(errOut, 1000))
	}
	if _, err := os.Stat(filepath.Join(c.work, "dc", "sandboxes", name, "copy")); !os.IsNotExist(err) {
		t.Fatalf("the refused run staged a copy for %s: %v", name, err)
	}

	out = c.okIn(dir, 15*time.Minute, "connect", name, "--prompt", "Write the allowed marker file.", "--yes")
	t.Logf("connect --prompt:\n%s", truncate(out, 2000))
	wantAll(t, "connect --prompt", out, "Session ended", "keeps running: its detached run is still going")
	if sb := c.status(name); sb.Phase != "ready" {
		t.Fatalf("phase after the headless session = %s", sb.Phase)
	}
	wantAll(t, "logs after the headless session", c.okIn(dir, time.Minute, "logs", name), "the run is still going")

	out = c.okIn(dir, 5*time.Minute, "stop", name)
	wantAll(t, "stop", out, "is still going; stopping the sandbox ends it", name+" is stopped")
	logs := c.okIn(dir, time.Minute, "logs", name)
	wantAll(t, "logs of the stopped sandbox", logs, "→ Bash: sleep 200", "this is the log kept when it stopped", "the run did not finish")

	c.okIn(dir, 5*time.Minute, "start", name)
	logs = c.okIn(dir, time.Minute, "logs", name)
	wantAll(t, "logs after the restart", logs, "the run did not finish")
	if strings.Contains(logs, "still going") {
		t.Fatalf("the interrupted run reads as going after the restart:\n%s", truncate(logs, 1000))
	}
	c.delete(name)
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
	// Codex's own tool calls reach the web through the DefenseClaw proxy
	// its launcher exports: a plain curl (no --proxy) in a tool call.
	argv, err := harness.Codex.LaunchArgv(harness.LaunchOptions{Mode: harness.Headless, Yolo: true,
		Prompt: "Run the DCE2E-FETCH scenario.", Args: c.codexMockArgs()})
	if err != nil {
		t.Fatal(err)
	}
	out, rc := c.execOut(c.codex, argv...)
	t.Logf("codex fetch exited %d: %s", rc, truncate(strings.TrimSpace(out), 300))
	if got, _ := c.execOut(c.codex, "cat", "/tmp/dce2e-fetch.txt"); strings.TrimSpace(got) != "200" {
		t.Fatalf("Codex's fetch of %s = %q, want 200 through the proxy", allowedHost, got)
	}
}

// runCopy starts a detached copy-mode Claude Code run of prompt in dir
// with the mock model, waits for it and checks that its hooks reached the
// ingress (`logs` fails a run none of whose hooks did).
func (c *cliEnv) runCopy(dir, name, prompt string) string {
	t := c.t
	started := time.Now()
	out := c.okIn(dir, 45*time.Minute, "run", "claude", "--copy", "--detach", "--name", name, "--llm", "none",
		"--credential", "ANTHROPIC_API_KEY=host.openshell.internal:"+strconv.Itoa(c.mock),
		"--env", "ANTHROPIC_BASE_URL=http://host.openshell.internal:"+strconv.Itoa(c.mock),
		"--", "-p", prompt)
	t.Logf("run --copy (%s):\n%s", time.Since(started).Round(time.Second), truncate(out, 3000))
	wantAll(t, "run output", out, "Sandbox "+name+" · Claude Code", "→ /sandbox/work/"+filepath.Base(dir)+" (copy)",
		"Uploading the copy", "held back: .env", "running in the background")
	code, logs := c.waitRun(name, 5*time.Minute)
	if code != 0 {
		t.Fatalf("the detached copy-mode harness exited %d:\n%s", code, logs)
	}
	sb := c.status(name)
	if sb.WorkdirMode != "copy" || sb.Workdir != "/sandbox/work/"+filepath.Base(dir) || sb.Hooks.HookRequests == 0 || sb.Hooks.Unreachable {
		t.Fatalf("copy-mode sandbox: mode %s, workdir %s, hooks %+v", sb.WorkdirMode, sb.Workdir, sb.Hooks)
	}
	return out
}

func (c *cliEnv) copyGitRun() {
	t := c.t
	c.runCopy(c.copyGitProj, c.copyGit, "Run the DCE2E-EDIT scenario.")
	// The edit is in the copy; the secret never left the host; the host
	// folder is untouched.
	inside, code := c.execOut(c.copyGit, "sh", "-c", "cat README.md; test -e .env || echo no-env; git rev-parse --is-inside-work-tree")
	if code != 0 {
		t.Fatalf("inside the copy (exit %d): %s", code, inside)
	}
	wantAll(t, "the copy", inside, "dce2e-edited", "no-env", "true")
	if got := c.readFile(filepath.Join(c.copyGitProj, "README.md")); got != c.readme {
		t.Fatalf("the host README changed during a copy-mode run: %q", got)
	}
}

func (c *cliEnv) copyGitPull() {
	t := c.t
	dir, name := c.copyGitProj, c.copyGit
	readme := filepath.Join(dir, "README.md")
	out := c.okIn(dir, 5*time.Minute, "pull", name)
	wantAll(t, "pull", out, "M README.md", "bring it back with --apply, --branch or --patch-out FILE")

	// --branch: dc/<name> holds the edit, the checkout stays as it was.
	out = c.okIn(dir, 5*time.Minute, "pull", name, "--branch")
	wantAll(t, "pull --branch", out, "the changes are on branch dc/"+name)
	wantAll(t, "the dc/ branch", c.gitIn(dir, "show", "dc/"+name+":README.md"), "dce2e-edited")
	if got := c.readFile(readme); got != c.readme {
		t.Fatalf("pull --branch changed the checkout: %q", got)
	}

	// --patch-out: the edit, and nothing of the held-back secret.
	patch := filepath.Join(c.work, name+".patch")
	c.okIn(dir, 5*time.Minute, "pull", name, "--patch-out", patch)
	data := c.readFile(patch)
	wantAll(t, "the patch", data, "README.md", "+dce2e-edited")
	if strings.Contains(data, ".env") || strings.Contains(data, "DCE2E_PLACEHOLDER") {
		t.Fatalf("the patch carries the held-back secret:\n%s", truncate(data, 2000))
	}

	// --apply over a conflicting host edit leaves the folder alone, falls
	// back to a branch and a patch, says how to merge, and exits 4.
	writeFile(t, readme, []byte("host edit during the session\n"), 0o644)
	out, _, code := c.cliIn(dir, 5*time.Minute, "pull", name, "--apply")
	t.Logf("pull --apply over a conflict (exit %d):\n%s", code, truncate(out, 2000))
	if code != sandboxcli.ExitPullConflict {
		t.Fatalf("pull --apply over a conflict exited %d, want %d", code, sandboxcli.ExitPullConflict)
	}
	wantAll(t, "pull --apply (conflict)", out, "the 3-way apply conflicted in README.md", "the changes are on branch dc/"+name+"-2", "and in ",
		"git merge dc/"+name+"-2")
	if got := c.readFile(readme); got != "host edit during the session\n" {
		t.Fatalf("a conflicting apply changed README: %q", got)
	}
	// The fallback patch sits in the project folder, where deleting the
	// sandbox cannot take it along.
	wantAll(t, "the fallback patch", c.readFile(filepath.Join(dir, name+".patch")), "+dce2e-edited")

	// --apply on a clean checkout lands the edit.
	c.gitIn(dir, "checkout", "--", "README.md")
	out = c.okIn(dir, 5*time.Minute, "pull", name, "--apply")
	wantAll(t, "pull --apply", out, "applied 1 change to", "`defenseclaw sandbox undo "+name+"` reverts the apply")
	wantAll(t, "README after --apply", c.readFile(readme), "dce2e-edited")
	if got := c.readFile(filepath.Join(dir, ".env")); got != "DCE2E_PLACEHOLDER=not-a-secret\n" {
		t.Fatalf("the held-back .env changed: %q", got)
	}

	// The same work again changes nothing and keeps the undo point.
	preRef := "refs/defenseclaw/copy/" + name + "/pre-apply"
	pre := c.gitIn(dir, "rev-parse", preRef)
	out = c.okIn(dir, 5*time.Minute, "pull", name, "--apply")
	wantAll(t, "pull --apply again", out, "nothing to apply:", "already has these changes")
	if now := c.gitIn(dir, "rev-parse", preRef); now != pre {
		t.Fatalf("a second apply of the same work moved %s from %s to %s", preRef, pre, now)
	}
	// undo reverts the apply (a copy-mode sandbox changes the folder only
	// that way); applying again brings the edit back for the next steps.
	out = c.okIn(dir, 5*time.Minute, "undo", name, "--yes")
	t.Logf("undo of the apply:\n%s", truncate(out, 2000))
	wantAll(t, "undo of the apply", out, "Undo will revert the last `pull --apply` of "+name, "revert  README.md", "reverted the last apply: 1 path")
	if got := c.readFile(readme); got != c.readme {
		t.Fatalf("README after the undo = %q", got)
	}
	out = c.okIn(dir, 5*time.Minute, "undo", name, "--yes")
	wantAll(t, "a second undo", out, "nothing to undo")
	out = c.okIn(dir, 5*time.Minute, "pull", name, "--apply")
	wantAll(t, "pull --apply after the undo", out, "applied 1 change to")
}

// copyGitRefresh resumes the stopped copy-mode sandbox with `connect
// --refresh` on a terminal (script(1)): the fresh copy carries a file
// created on the host since, and still not the secret.
func (c *cliEnv) copyGitRefresh() {
	t := c.t
	script, err := exec.LookPath("script")
	if err != nil || runtime.GOOS != "linux" {
		t.Skip("util-linux script(1) is needed to give the CLI a terminal")
	}
	dir, name := c.copyGitProj, c.copyGit
	c.okIn(dir, 5*time.Minute, "stop", name)
	writeFile(t, filepath.Join(dir, "refreshed.txt"), []byte("new on the host\n"), 0o644)
	bin := filepath.Join(c.work, "bin", "defenseclaw-gateway")
	inner := shellJoin(bin, "sandbox", "connect", name, "--refresh", "--yes", "--", "-p", "Write the allowed marker file.")
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, script, "-q", "-e", "-f", "-c", inner, "/dev/null")
	cmd.Dir, cmd.Env = dir, c.cliEnviron()
	raw, err := cmd.CombinedOutput()
	out := string(raw)
	t.Logf("connect --refresh:\n%s", truncate(out, 3000))
	if err != nil {
		t.Fatalf("connect --refresh: %v", err)
	}
	wantAll(t, "connect --refresh", out, "starting "+name, "refreshing the project copy in "+name, "Session ended")
	if strings.Contains(out, "not reaching the daemon") {
		t.Fatal("the resumed session's hooks did not reach DefenseClaw")
	}
	// The session stopped the sandbox; start it to look at the new copy.
	c.okIn(dir, 5*time.Minute, "start", name)
	inside, code := c.execOut(name, "sh", "-c", "cat refreshed.txt; test -e .env || echo no-env; grep -c dce2e-edited README.md")
	if code != 0 {
		t.Fatalf("inside the refreshed copy (exit %d): %s", code, inside)
	}
	wantAll(t, "the refreshed copy", inside, "new on the host", "no-env", "1")
}

// copyPlainRun runs a folder that is not a git repository in copy mode:
// the hidden git dir stays outside it, there is no branch to pull to, and
// --apply lands the edit without creating a repository on the host.
func (c *cliEnv) copyPlainRun() {
	t := c.t
	dir, name := c.copyPlainProj, c.copyPlain
	c.runCopy(dir, name, "Run the DCE2E-EDIT scenario.")
	inside, code := c.execOut(name, "sh", "-c", "cat README.md; test -e .git || echo no-git; test -e .env || echo no-env; test -f /sandbox/.dc/git/HEAD && echo hidden-git")
	if code != 0 {
		t.Fatalf("inside the plain copy (exit %d): %s", code, inside)
	}
	wantAll(t, "the plain copy", inside, "dce2e-edited", "no-git", "no-env", "hidden-git")
	if got := c.readFile(filepath.Join(dir, "README.md")); got != c.readme {
		t.Fatalf("the host README changed during a copy-mode run: %q", got)
	}
	_, errOut, code := c.cliIn(dir, 5*time.Minute, "pull", name, "--branch")
	if code == 0 || !strings.Contains(errOut, "not a git repository") || !strings.Contains(errOut, "--apply or --patch-out") {
		t.Fatalf("pull --branch of a plain folder exited %d: %s", code, truncate(errOut, 1000))
	}
	// A pull from a stopped sandbox starts it to read its work and stops
	// it again.
	c.okIn(dir, 5*time.Minute, "stop", name)
	patch := filepath.Join(c.work, name+".patch")
	out := c.okIn(dir, 5*time.Minute, "pull", name, "--patch-out", patch)
	wantAll(t, "pull from a stopped sandbox", out, "starting "+name, "stopped "+name+" again")
	if phase := c.status(name).Phase; phase != "stopped" {
		t.Fatalf("the pull left %s %s", name, phase)
	}
	wantAll(t, "the plain patch", c.readFile(patch), "+dce2e-edited")
	out = c.okIn(dir, 5*time.Minute, "pull", name, "--apply")
	wantAll(t, "pull --apply", out, "applied 1 change to")
	wantAll(t, "README after --apply", c.readFile(filepath.Join(dir, "README.md")), "dce2e-edited")
	if _, err := os.Lstat(filepath.Join(dir, ".git")); err == nil {
		t.Fatal("copy mode created a git repository in the plain folder")
	}
	if got := c.readFile(filepath.Join(dir, ".env")); got != "DCE2E_PLACEHOLDER=not-a-secret\n" {
		t.Fatalf("the held-back .env changed: %q", got)
	}
}

func (c *cliEnv) bedrockClaude() {
	t := c.t
	if os.Getenv("AWS_BEARER_TOKEN_BEDROCK") == "" {
		t.Skip("AWS_BEARER_TOKEN_BEDROCK is not set")
	}
	c.environ = append(c.cliEnviron(), "AWS_BEARER_TOKEN_BEDROCK="+os.Getenv("AWS_BEARER_TOKEN_BEDROCK"))
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
	// No -m: Codex on Mantle runs the profile's default model (Codex's own
	// default is not served there), and the banner says which.
	out := c.ok(45*time.Minute, "run", "codex", "--detach", "--new", "--name", name, "--llm", "bedrock", "--bedrock-region", envOr("AWS_REGION", "us-east-1"),
		"--prompt", "Run `echo dce2e-allowed > /tmp/dce2e-allowed.txt` in the shell, then say done.")
	if !strings.Contains(out, "Model     "+harness.CodexMantleDefaultModel+" (the default; -- -m MODEL picks another) · ") {
		t.Fatalf("the banner does not name the default model:\n%s", out)
	}
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
