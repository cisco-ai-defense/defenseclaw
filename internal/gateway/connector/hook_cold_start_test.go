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
)

// A per-user Linux or macOS gateway has no service unit, so after a reboot
// the shell hooks start it: a refused request (curl exit 7) runs
// `defenseclaw-gateway start --hook-cold-start` once and is retried.
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
if [ "$n" = 1 ]; then exit "${DC_COLD_FIRST_RC:-7}"; fi
printf '%s\n%s\n' '{"action":"allow","codex_output":{"decision":"allow"}}' '200'
`

const coldStartGatewayStub = `#!/bin/sh
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
	if err := WriteHookScriptsForConnectorObject(hooksDir, "127.0.0.1:18970", "cold-start-scoped-token", c); err != nil {
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
				t.Fatalf("curl ran %q times, want 2 (refused, then retried)", got)
			}
			log := strings.TrimSpace(readColdStartCapture(t, run.capDir, "gateway.log"))
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
			// The retry sends the same request: same body and, for Codex, the
			// same credential through a fresh descriptor.
			if first, second := readColdStartCapture(t, run.capDir, "body.1"), readColdStartCapture(t, run.capDir, "body.2"); first == "" || first != second {
				t.Errorf("retry body = %q, want the first body %q", second, first)
			}
			if tc.name == "codex" {
				if first, second := readColdStartCapture(t, run.capDir, "config.1"), readColdStartCapture(t, run.capDir, "config.2"); !strings.Contains(second, "cold-start-scoped-token") || first != second {
					t.Errorf("retry did not resend the scoped credential (first %d bytes, second %d bytes)", len(first), len(second))
				}
			}
		})
	}
}

func TestShellHookDoesNotColdStartAStoppedGateway(t *testing.T) {
	cases := map[string]struct {
		prepare func(string)
		env     []string
		hint    string
	}{
		// The hook names the way back (SWEEP-16): an explicit stop is never
		// undone by a hook, so the user has to start the gateway.
		"stopped with defenseclaw-gateway stop": {prepare: func(dataDir string) {
			_ = os.WriteFile(filepath.Join(dataDir, "gateway.stopped"), []byte("stopped\n"), 0o600)
		}, hint: "stopped with `defenseclaw-gateway stop`; run `defenseclaw-gateway start` to resume protection"},
		"install in progress": {prepare: func(dataDir string) {
			_ = os.Mkdir(filepath.Join(dataDir, ".install.lock"), 0o700)
		}, hint: "gateway is not running; run `defenseclaw-gateway start`"},
		"no configuration": {prepare: func(dataDir string) {
			_ = os.Remove(filepath.Join(dataDir, "config.yaml"))
		}, hint: "gateway is not running; run `defenseclaw-gateway start`"},
		"autostart off": {env: []string{"DEFENSECLAW_GATEWAY_AUTOSTART=0"}, hint: "run `defenseclaw-gateway start`"},
		"managed hook":  {env: []string{"DEFENSECLAW_MANAGED_HOOK=1"}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			// Fail open, as in observe mode: Claude Code then hides stderr.
			env := append([]string{"DEFENSECLAW_FAIL_MODE=open"}, tc.env...)
			run := runHookForColdStart(t, NewClaudeCodeConnector(), "claude-code-hook.sh", nil, tc.prepare, env...)
			if log := readColdStartCapture(t, run.capDir, "gateway.log"); log != "" {
				t.Fatalf("hook started the gateway: %q", log)
			}
			if got := strings.TrimSpace(readColdStartCapture(t, run.capDir, "count")); got != "1" {
				t.Fatalf("curl ran %q times, want 1", got)
			}
			if !strings.Contains(run.stderr, "gateway unreachable") {
				t.Fatalf("stderr = %q, want the unreachable report", run.stderr)
			}
			if tc.hint != "" && !strings.Contains(run.stderr, tc.hint) {
				t.Errorf("stderr = %q, want the next step %q", run.stderr, tc.hint)
			}
			if tc.hint == "" && strings.Contains(run.stderr, "defenseclaw-gateway start") {
				t.Errorf("stderr = %q, want no start advice", run.stderr)
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
	if code := exitCodeOf(run.err); code != 2 {
		t.Fatalf("exit code = %d, want 2 (fail closed)", code)
	}
	if log := readColdStartCapture(t, run.capDir, "gateway.log"); log != "" {
		t.Fatalf("a timed-out request started the gateway: %q", log)
	}

	open := runHookForColdStart(t, NewClaudeCodeConnector(), "claude-code-hook.sh", nil, alive,
		"DEFENSECLAW_FAIL_MODE=open", "DC_COLD_FIRST_RC=28")
	if !strings.Contains(open.stdout, "the gateway is running but did not answer. Run `defenseclaw-gateway restart`") {
		t.Errorf("fail-open stdout = %q, want the restart notice", open.stdout)
	}
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
		!strings.Contains(out.SystemMessage, "Run `defenseclaw-gateway start` to resume protection.") {
		t.Errorf("systemMessage = %q, want the gateway-down notice with the start step", out.SystemMessage)
	}
}
