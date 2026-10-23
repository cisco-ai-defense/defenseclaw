// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package connector

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// A per-user Linux or macOS gateway has no service unit, so after a reboot
// the shell hooks start it: a refused request (curl exit 7) starts
// `defenseclaw-gateway start --hook-cold-start` in the background once and
// is sent again while it starts. The stub fails the first DC_COLD_FAILS
// requests (default 1) with DC_COLD_FIRST_RC (default 7).
const coldStartCurlStub = `#!/bin/sh
n=$(cat "$DC_COLD_CAP/count" 2>/dev/null || echo 0)
n=$((n + 1))
echo "$n" > "$DC_COLD_CAP/count"
want=""
for arg in "$@"; do
  case "$want" in
    body)
      case "$arg" in
        @*) cat "${arg#@}" > "$DC_COLD_CAP/body.$n" ;;
        *) printf '%s' "$arg" > "$DC_COLD_CAP/body.$n" ;;
      esac
      want="" ;;
    config) cat "$arg" > "$DC_COLD_CAP/config.$n"; want="" ;;
  esac
  case "$arg" in
    -d|--data|--data-binary) want=body ;;
    -K|--config) want=config ;;
  esac
done
if [ "$n" -le "${DC_COLD_FAILS:-1}" ]; then exit "${DC_COLD_FIRST_RC:-7}"; fi
printf '%s\n%s\n' '{"action":"allow","codex_output":{"decision":"allow"}}' '200'
`

// The stub records only starts: the hook also asks the binary for session
// facts (on macOS always, elsewhere when a credential cache can exist), and
// that read never starts a gateway.
const coldStartGatewayStub = `#!/bin/sh
[ "$1" = hook ] && exit 0
printf '%s|%s|%s|%s|%s\n' "$HOME" "$*" "$(ulimit -S -t)" "$(ulimit -H -t)" "${DEFENSECLAW_GATEWAY_TOKEN+inherited}" >> "$DC_COLD_CAP/gateway.log"
exit 0
`

type coldStartHookRun struct {
	capDir  string
	dataDir string
	home    string
	stdout  string
	stderr  string
	err     error
}

func runHookForColdStart(t *testing.T, c Connector, script string, args []string, prepare func(dataDir string), extraEnv ...string) coldStartHookRun {
	t.Helper()
	hooksDir := t.TempDir()
	if err := writePerUserHooksForTestFailMode(hooksDir, freeAPIAddr(t), "cold-start-scoped-token", c, extraEnv); err != nil {
		t.Fatalf("write hooks: %v", err)
	}
	stubDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(stubDir, "curl"), []byte(coldStartCurlStub), 0o755); err != nil {
		t.Fatal(err)
	}
	hookPath := filepath.Join(hooksDir, script)
	bakeHookPathForTest(t, hookPath, stubDir+":/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin")

	home := t.TempDir()
	dataDir := filepath.Join(home, ".defenseclaw")
	binDir := filepath.Join(home, ".local", "bin")
	for _, dir := range []string{dataDir, binDir} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dataDir, "config.yaml"), []byte("gateway: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(binDir, "defenseclaw-gateway"), []byte(coldStartGatewayStub), 0o755); err != nil {
		t.Fatal(err)
	}
	if prepare != nil {
		prepare(dataDir)
	}
	capDir := t.TempDir()

	env := make([]string, 0, 64)
	for _, entry := range sanitizedTestEnv() {
		name, _, _ := strings.Cut(entry, "=")
		if name == "HOME" || name == "DEFENSECLAW_GATEWAY_AUTOSTART" {
			continue
		}
		env = append(env, entry)
	}
	env = append(env, "HOME="+home, "DEFENSECLAW_HOME="+dataDir, "DC_COLD_CAP="+capDir)
	env = append(env, extraEnv...)

	cmd := exec.Command("bash", append([]string{hookPath}, args...)...)
	cmd.Env = env
	cmd.Stdin = strings.NewReader(`{"hook_event_name":"PreToolUse","tool_name":"Read","cold":"start-payload"}`)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	return coldStartHookRun{capDir: capDir, dataDir: dataDir, home: home, stdout: stdout.String(), stderr: stderr.String(), err: err}
}

// waitColdStartCapture waits for the background start to write name.
func waitColdStartCapture(t *testing.T, dir, name string) string {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		if got := readColdStartCapture(t, dir, name); got != "" {
			return got
		}
	}
	return ""
}

func readColdStartCapture(t *testing.T, dir, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		if os.IsNotExist(err) {
			return ""
		}
		t.Fatal(err)
	}
	return string(data)
}

func TestShellHooksColdStartTheGatewayAfterARefusedRequest(t *testing.T) {
	cases := []struct {
		name   string
		c      Connector
		script string
		args   func(t *testing.T, hookPath string) []string
	}{
		{name: "claude-code", c: NewClaudeCodeConnector(), script: "claude-code-hook.sh"},
		{name: "codex", c: NewCodexConnector(), script: "codex-hook.sh", args: func(t *testing.T, hookPath string) []string {
			return codexBoundShellHookArgsForTest(t, hookPath, "PreToolUse")[1:]
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var args []string
			if tc.args != nil {
				args = tc.args(t, tc.script)
			}
			run := runHookForColdStart(t, tc.c, tc.script, args, nil)
			if run.err != nil {
				t.Fatalf("hook failed: %v\nstderr=%s", run.err, run.stderr)
			}
			if strings.Contains(run.stderr, "unreachable") {
				t.Fatalf("the retried request still reported the gateway unreachable: %s", run.stderr)
			}
			if got := strings.TrimSpace(readColdStartCapture(t, run.capDir, "count")); got != "2" {
				t.Fatalf("curl ran %q times, want 2 (refused, then sent again)", got)
			}
			log := strings.TrimSpace(waitColdStartCapture(t, run.capDir, "gateway.log"))
			fields := strings.Split(log, "|")
			if len(fields) != 5 || strings.Contains(log, "\n") {
				t.Fatalf("gateway start ran %q, want exactly one start", log)
			}
			if fields[0] != run.home {
				t.Errorf("gateway start HOME = %q, want the account's HOME %q, not the hook's private one", fields[0], run.home)
			}
			if fields[1] != "start --hook-cold-start" {
				t.Errorf("gateway start args = %q", fields[1])
			}
			if fields[2] != fields[3] {
				t.Errorf("gateway start kept the hook's CPU soft limit %q (hard %q)", fields[2], fields[3])
			}
			// The hook's token is the connector-scoped one: a gateway that took
			// it from DEFENSECLAW_GATEWAY_TOKEN would make it its own.
			if fields[4] != "" {
				t.Errorf("the started gateway inherited the hook's DEFENSECLAW_GATEWAY_TOKEN")
			}
			// The retry sends the same request: the same body and the same
			// credential, each through a fresh descriptor.
			if first, second := readColdStartCapture(t, run.capDir, "body.1"), readColdStartCapture(t, run.capDir, "body.2"); first == "" || first != second {
				t.Errorf("retry body = %q, want the first body %q", second, first)
			}
			if first, second := readColdStartCapture(t, run.capDir, "config.1"), readColdStartCapture(t, run.capDir, "config.2"); !strings.Contains(second, "cold-start-scoped-token") || first != second {
				t.Errorf("retry did not resend the scoped credential (first %d bytes, second %d bytes)", len(first), len(second))
			}
		})
	}
}

func TestShellHookDoesNotColdStartAStoppedGateway(t *testing.T) {
	// Without a start, a refused call is still sent again for the restart
	// budget (a restart or an upgrade may be under way), then reported.
	const waited = "restarting or not running (no answer within 3 seconds); try again in a moment, or run `defenseclaw-gateway start`"
	// An install or upgrade stops the gateway like an operator does and
	// starts it again when it is done: a restart, not a stop (GAP-0140).
	const installing = "DefenseClaw is being installed or upgraded for this account and its gateway starts again when that is done"
	cases := map[string]struct {
		prepare func(string)
		env     []string
		hint    string
		retried bool
		closed  bool
	}{
		// The hook names the way back (SWEEP-16): an explicit stop is never
		// undone by a hook, so the user has to start the gateway.
		"stopped with defenseclaw-gateway stop": {prepare: func(dataDir string) {
			_ = os.WriteFile(filepath.Join(dataDir, "gateway.stopped"), []byte("stopped\n"), 0o600)
		}, hint: "stopped with `defenseclaw-gateway stop`; run `defenseclaw-gateway start` to resume protection"},
		"install in progress": {prepare: func(dataDir string) {
			_ = os.Mkdir(filepath.Join(dataDir, ".install.lock"), 0o700)
		}, hint: installing, retried: true, closed: true},
		"stopped by an upgrade in progress": {prepare: func(dataDir string) {
			_ = os.Mkdir(filepath.Join(dataDir, ".install.lock"), 0o700)
			_ = os.WriteFile(filepath.Join(dataDir, "gateway.stopped"), []byte("stopped\n"), 0o600)
		}, hint: installing, retried: true, closed: true},
		"no configuration": {prepare: func(dataDir string) {
			_ = os.Remove(filepath.Join(dataDir, "config.yaml"))
		}, hint: waited, retried: true},
		"autostart off": {env: []string{"DEFENSECLAW_GATEWAY_AUTOSTART=0"}, hint: waited, retried: true},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			// An open install still closes while the installer owns the lock.
			env := append([]string{"DEFENSECLAW_FAIL_MODE=open", "DC_COLD_FAILS=1000"}, tc.env...)
			run := runHookForColdStart(t, NewClaudeCodeConnector(), "claude-code-hook.sh", nil, tc.prepare, env...)
			time.Sleep(200 * time.Millisecond) // a background start would have logged by now
			if log := readColdStartCapture(t, run.capDir, "gateway.log"); log != "" {
				t.Fatalf("hook started the gateway: %q", log)
			}
			count, _ := strconv.Atoi(strings.TrimSpace(readColdStartCapture(t, run.capDir, "count")))
			if tc.retried && count < 2 {
				t.Fatalf("curl ran %d times, want the call sent again", count)
			}
			if !tc.retried && count != 1 {
				t.Fatalf("curl ran %d times, want 1", count)
			}
			if !strings.Contains(run.stderr, "gateway unreachable") {
				t.Fatalf("stderr = %q, want the unreachable report", run.stderr)
			}
			if tc.hint != "" && !strings.Contains(run.stderr, tc.hint) {
				t.Errorf("stderr = %q, want the next step %q", run.stderr, tc.hint)
			}
			// GAP-0090, GAP-0093: the next step names the status command
			// and no Windows one.
			if tc.hint != "" && (!strings.Contains(run.stderr, "`defenseclaw-gateway status`") ||
				strings.Contains(run.stderr, ".exe") || strings.Contains(run.stderr, "PowerShell")) {
				t.Errorf("stderr = %q, want `defenseclaw-gateway status` named and no Windows command", run.stderr)
			}
			if tc.hint == "" && strings.Contains(run.stderr, "defenseclaw-gateway start") {
				t.Errorf("stderr = %q, want no start advice", run.stderr)
			}
			if tc.closed {
				if !strings.Contains(run.stdout, `"permissionDecision":"deny"`) ||
					!strings.Contains(run.stdout, "is being installed or upgraded for this account") ||
					!strings.Contains(run.stdout, "defenseclaw-gateway status") ||
					strings.Contains(run.stdout, "stopped with") || strings.Contains(run.stdout, "systemMessage") {
					t.Errorf("stdout = %q, want the install-time native deny and next step", run.stdout)
				}
				return
			}
			// Claude Code hides stderr of a hook that exits 0, so the next
			// step is also on stdout as a systemMessage (GAP-0037).
			assertGatewayDownNotice(t, run.stdout, tc.hint != "")
		})
	}
}

// A frozen or hung gateway keeps its listener, so the request times out
// (curl 28) while gateway.pid names a live process. The line says so once,
// with the next step, instead of "gateway unreachable ...: gateway
// unreachable" (GAP-1204).
func TestShellHookNamesTheNextStepForAHungGateway(t *testing.T) {
	alive := func(dataDir string) {
		_ = os.WriteFile(filepath.Join(dataDir, "gateway.pid"), []byte(strconv.Itoa(os.Getpid())+"\n"), 0o600)
	}
	run := runHookForColdStart(t, NewClaudeCodeConnector(), "claude-code-hook.sh", nil, alive,
		"DEFENSECLAW_FAIL_MODE=closed", "DC_COLD_FIRST_RC=28")
	want := "defenseclaw: gateway unreachable, blocking claude-code tool (fail mode closed): " +
		"the gateway is running but did not answer; check `defenseclaw-gateway status`, or run `defenseclaw-gateway restart`"
	if got := strings.TrimSpace(run.stderr); got != want {
		t.Fatalf("stderr = %q\nwant %q", got, want)
	}
	if reason := failClosedDenyReason(t, run); !strings.Contains(reason, "the gateway is running but did not answer") {
		t.Fatalf("deny reason = %q, want the hung-gateway step", reason)
	}
	if log := readColdStartCapture(t, run.capDir, "gateway.log"); log != "" {
		t.Fatalf("a timed-out request started the gateway: %q", log)
	}
	if got := strings.TrimSpace(readColdStartCapture(t, run.capDir, "count")); got != "1" {
		t.Fatalf("curl ran %q times, want 1: a gateway that accepted the call keeps it", got)
	}

	open := runHookForColdStart(t, NewClaudeCodeConnector(), "claude-code-hook.sh", nil, alive,
		"DEFENSECLAW_FAIL_MODE=open", "DC_COLD_FIRST_RC=28")
	if !strings.Contains(open.stdout, "the gateway is running but did not answer. Run `defenseclaw-gateway restart`") {
		t.Errorf("fail-open stdout = %q, want the restart notice", open.stdout)
	}
}

// GAP-0409: when the last start failed because config.yaml does not load, a
// fail-closed hook says so instead of "run defenseclaw-gateway start".
func TestShellHookNamesAConfigThatDoesNotLoad(t *testing.T) {
	broken := func(dataDir string) {
		past := time.Now().Add(-time.Hour)
		_ = os.Chtimes(filepath.Join(dataDir, "config.yaml"), past, past)
		_ = os.WriteFile(filepath.Join(dataDir, "gateway.cold-start-failed"), []byte("2026-10-07T00:00:00Z\nconfig-invalid\n"), 0o600)
	}
	run := runHookForColdStart(t, NewClaudeCodeConnector(), "claude-code-hook.sh", nil, broken,
		"DEFENSECLAW_FAIL_MODE=closed", "DEFENSECLAW_GATEWAY_AUTOSTART=0", "DC_COLD_FAILS=1000")
	if !strings.Contains(run.stderr, "config.yaml does not load; run `defenseclaw config validate`") {
		t.Fatalf("stderr = %q, want the config.yaml cause", run.stderr)
	}
	if reason := failClosedDenyReason(t, run); !strings.Contains(reason, "config.yaml does not load") {
		t.Fatalf("deny reason = %q, want the config.yaml cause", reason)
	}
}

// GAP-1074: for an exit-2 block Claude Code prints the whole hook command
// line, guard clause included, in front of the reason. A fail-closed tool
// call is denied with Claude's JSON decision instead: one plain sentence,
// no shell syntax, no DefenseClaw file paths, and no claim about who stopped
// the gateway (an upgrade stops it too).
func TestClaudeShellHookFailClosedDenyIsOnePlainSentence(t *testing.T) {
	stopped := func(dataDir string) {
		_ = os.WriteFile(filepath.Join(dataDir, "gateway.stopped"), []byte("stopped\n"), 0o600)
	}
	run := runHookForColdStart(t, NewClaudeCodeConnector(), "claude-code-hook.sh", nil, stopped,
		"DEFENSECLAW_FAIL_MODE=closed")
	reason := failClosedDenyReason(t, run)
	want := "DefenseClaw blocked this because its gateway is stopped. Run defenseclaw-gateway start to resume protection."
	if reason != want {
		t.Fatalf("deny reason = %q\nwant %q", reason, want)
	}

	// A per-user hook is never a managed one: a DEFENSECLAW_MANAGED_HOOK
	// inherited from the agent's environment does not switch it to the
	// managed answer (1.0.4 review, GAP-0315).
	inherited := runHookForColdStart(t, NewClaudeCodeConnector(), "claude-code-hook.sh", nil, stopped,
		"DEFENSECLAW_FAIL_MODE=closed", "DEFENSECLAW_MANAGED_HOOK=1")
	if got := failClosedDenyReason(t, inherited); got != want {
		t.Fatalf("inherited managed marker: deny reason = %q\nwant %q", got, want)
	}
}

// failClosedDenyReason returns the reason of the PreToolUse deny decision a
// fail-closed per-user Claude Code hook prints, and fails unless the hook
// exited 0 with exactly that decision.
func failClosedDenyReason(t *testing.T, run coldStartHookRun) string {
	t.Helper()
	if code := exitCodeOf(run.err); code != 0 {
		t.Fatalf("exit code = %d, want 0 with a JSON deny decision; stderr=%q", code, run.stderr)
	}
	var decision struct {
		HookSpecificOutput struct {
			HookEventName      string `json:"hookEventName"`
			PermissionDecision string `json:"permissionDecision"`
			Reason             string `json:"permissionDecisionReason"`
		} `json:"hookSpecificOutput"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(run.stdout)), &decision); err != nil ||
		decision.HookSpecificOutput.HookEventName != "PreToolUse" ||
		decision.HookSpecificOutput.PermissionDecision != "deny" {
		t.Fatalf("stdout = %q, want one PreToolUse deny decision", run.stdout)
	}
	reason := decision.HookSpecificOutput.Reason
	if strings.ContainsAny(reason, "`{}|") || strings.Contains(reason, ".defenseclaw/") {
		t.Fatalf("deny reason %q shows shell syntax or an internal path", reason)
	}
	return reason
}

func exitCodeOf(err error) int {
	if err == nil {
		return 0
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode()
	}
	return -1
}

// Codex, like Claude Code, shows only the systemMessage of a fail-open hook.
func TestCodexShellHookShowsTheStartStepWhenTheGatewayWasStopped(t *testing.T) {
	run := runHookForColdStart(t, NewCodexConnector(), "codex-hook.sh",
		codexBoundShellHookArgsForTest(t, "codex-hook.sh", "PreToolUse")[1:],
		func(dataDir string) {
			_ = os.WriteFile(filepath.Join(dataDir, "gateway.stopped"), []byte("stopped\n"), 0o600)
		}, "DEFENSECLAW_FAIL_MODE=open")
	if run.err != nil {
		t.Fatalf("hook failed: %v\nstderr=%s", run.err, run.stderr)
	}
	assertGatewayDownNotice(t, run.stdout, true)
	if !strings.Contains(run.stdout, "stopped with `defenseclaw-gateway stop`") {
		t.Errorf("stdout = %q, want the stop named", run.stdout)
	}
}

func assertGatewayDownNotice(t *testing.T, stdout string, want bool) {
	t.Helper()
	if !want {
		if strings.TrimSpace(stdout) != "" {
			t.Errorf("stdout = %q, want no notice", stdout)
		}
		return
	}
	var out struct {
		SystemMessage string `json:"systemMessage"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(stdout)), &out); err != nil {
		t.Fatalf("stdout = %q, want one JSON hook result: %v", stdout, err)
	}
	if !strings.HasPrefix(out.SystemMessage, "DefenseClaw is not checking this session") ||
		!strings.Contains(out.SystemMessage, "Run `defenseclaw-gateway start` to resume protection.") ||
		!strings.Contains(out.SystemMessage, "`defenseclaw-gateway status`") || strings.Contains(out.SystemMessage, ".exe") {
		t.Errorf("systemMessage = %q, want the gateway-down notice with the start and status steps", out.SystemMessage)
	}
}

// GAP-0094, GAP-0102, GAP-0107: during a per-user gateway restart a call is
// refused (nobody listens yet) or dropped unanswered (the old gateway
// exits). It is sent again until the gateway that comes up answers it,
// within 3 seconds of the hook's start.
func TestShellHookIsAnsweredByTheGatewayThatRestarts(t *testing.T) {
	for _, tc := range []struct {
		name, rc string
		started  bool
	}{
		{name: "refused", rc: "7", started: true},
		{name: "empty reply", rc: "52"},
		{name: "reset", rc: "56"},
	} {
		for _, hook := range []struct {
			c      Connector
			script string
		}{
			{NewClaudeCodeConnector(), "claude-code-hook.sh"},
			{NewCodexConnector(), "codex-hook.sh"},
		} {
			t.Run(tc.name+"/"+hook.script, func(t *testing.T) {
				t.Parallel()
				var args []string
				if hook.script == "codex-hook.sh" {
					args = codexBoundShellHookArgsForTest(t, hook.script, "PreToolUse")[1:]
				}
				started := time.Now()
				run := runHookForColdStart(t, hook.c, hook.script, args, nil,
					"DEFENSECLAW_FAIL_MODE=closed", "DC_COLD_FAILS=3", "DC_COLD_FIRST_RC="+tc.rc)
				if elapsed := time.Since(started); elapsed > 3*time.Second {
					t.Fatalf("the call took %s", elapsed)
				}
				if run.err != nil || strings.Contains(run.stdout, "deny") || strings.Contains(run.stderr, "unreachable") {
					t.Fatalf("err=%v stdout=%q stderr=%q, want the restarted gateway's allow", run.err, run.stdout, run.stderr)
				}
				if got := strings.TrimSpace(readColdStartCapture(t, run.capDir, "count")); got != "4" {
					t.Fatalf("curl ran %q times, want 4 (three failed tries, then the answer)", got)
				}
				if tc.started {
					if log := strings.TrimSpace(waitColdStartCapture(t, run.capDir, "gateway.log")); strings.Count(log, "start --hook-cold-start") != 1 {
						t.Fatalf("gateway starts = %q, want exactly one", log)
					}
				} else {
					time.Sleep(200 * time.Millisecond)
					if log := readColdStartCapture(t, run.capDir, "gateway.log"); log != "" {
						t.Fatalf("a dropped call started the gateway: %q", log)
					}
				}
			})
		}
	}
}

// A restart or outage longer than the budget blocks the call within about
// 3 seconds, with the restart named, and never allows it (fail mode closed).
func TestShellHookBlocksWhenTheRestartOutlastsTheBudget(t *testing.T) {
	for _, rc := range []string{"7", "56"} {
		t.Run("claude-code/"+rc, func(t *testing.T) {
			t.Parallel()
			started := time.Now()
			run := runHookForColdStart(t, NewClaudeCodeConnector(), "claude-code-hook.sh", nil, nil,
				"DEFENSECLAW_FAIL_MODE=closed", "DC_COLD_FAILS=1000", "DC_COLD_FIRST_RC="+rc)
			assertBlockedWithinTheRestartBudget(t, started)
			if rc == "7" && waitColdStartCapture(t, run.capDir, "gateway.log") == "" {
				t.Fatal("a refused call did not start the gateway")
			}
			if reason := failClosedDenyReason(t, run); !strings.Contains(reason, "restarting or not running") {
				t.Fatalf("deny reason = %q, want the restart named", reason)
			}
		})
		t.Run("codex/"+rc, func(t *testing.T) {
			t.Parallel()
			started := time.Now()
			run := runHookForColdStart(t, NewCodexConnector(), "codex-hook.sh",
				codexBoundShellHookArgsForTest(t, "codex-hook.sh", "PreToolUse")[1:], nil,
				"DEFENSECLAW_FAIL_MODE=closed", "DC_COLD_FAILS=1000", "DC_COLD_FIRST_RC="+rc)
			assertBlockedWithinTheRestartBudget(t, started)
			if rc == "7" && waitColdStartCapture(t, run.capDir, "gateway.log") == "" {
				t.Fatal("a refused call did not start the gateway")
			}
			if code := exitCodeOf(run.err); !codexBlockAnswer("PreToolUse", code, run.stdout) || !strings.Contains(run.stderr, "blocking codex tool") ||
				!strings.Contains(run.stderr, "restarting or not running") {
				t.Fatalf("exit %d stderr %q, want a block naming the restart", code, run.stderr)
			}
		})
	}
}

func assertBlockedWithinTheRestartBudget(t *testing.T, started time.Time) {
	t.Helper()
	// bash 3.2 (macOS) counts whole seconds, so the end can come up to a
	// second early there.
	if elapsed := time.Since(started); elapsed < 1500*time.Millisecond || elapsed > 4500*time.Millisecond {
		t.Fatalf("the call was blocked after %s, want about 3 s", elapsed)
	}
}
