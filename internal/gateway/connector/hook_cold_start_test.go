// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package connector

import (
	"bytes"
	"encoding/json"
	"errors"
	"net"
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
# When each try reached the gateway (ns), for the restart-budget window.
ts=$(date +%s%N 2>/dev/null)
case "$ts" in ""|*[!0-9]*) ts=$(perl -MTime::HiRes=time -e 'printf("%.0f", time()*1e9)' 2>/dev/null) ;; esac
[ -z "$ts" ] || echo "$ts" >> "$DC_COLD_CAP/tries"
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

// The stub records native hook-post calls and starts separately. A shell
// hook sends its body and token to hook-post on stdin, then may cold start
// the gateway after a refused call.
const coldStartGatewayStub = `#!/bin/bash
[ "$1" = hook ] && exit 0
if [ "$1" = hook-outage-mode ]; then printf '%s\n' "${DC_COLD_OUTAGE_MODE:-closed}"; exit 0; fi
if [ "$1" = hook-post ]; then
  n=0
  if [ -f "$DC_COLD_CAP/count" ]; then IFS= read -r n < "$DC_COLD_CAP/count" || true; fi
  n=$((n + 1))
  printf '%s\n' "$n" > "$DC_COLD_CAP/count"
  ts=$(date +%s%N 2>/dev/null)
  case "$ts" in ""|*[!0-9]*) ts=$(perl -MTime::HiRes=time -e 'printf("%.0f", time()*1e9)' 2>/dev/null) ;; esac
  [ -z "$ts" ] || echo "$ts" >> "$DC_COLD_CAP/tries"
  cat > "$DC_COLD_CAP/body.$n"
  cp "$DC_COLD_CAP/body.$n" "$DC_COLD_CAP/config.$n"
  if [ "$n" -le "${DC_COLD_FAILS:-1}" ]; then
    if [ "${DC_COLD_DROP_LISTENER:-0}" = 1 ]; then
      : > "$DC_COLD_CAP/drop.$n"
      i=0
      while [ ! -e "$DC_COLD_CAP/dropped.$n" ] && [ "$i" -lt 100 ]; do
        sleep .01
        i=$((i + 1))
      done
    fi
    exit "${DC_COLD_FIRST_RC:-7}"
  fi
  printf '%s\n%s\n' '{"action":"allow","codex_output":{"decision":"allow"}}' '200'
  exit 0
fi
printf '%s|%s|%s|%s|%s\n' "$HOME" "$*" "$(ulimit -S -t)" "$(ulimit -H -t)" "${DEFENSECLAW_GATEWAY_TOKEN+inherited}" >> "$DC_COLD_CAP/gateway.log"
exit 0
`

type coldStartHookRun struct {
	capDir   string
	dataDir  string
	home     string
	hooksDir string
	stdout   string
	stderr   string
	err      error
	elapsed  time.Duration
}

func runHookForColdStart(t *testing.T, c Connector, script string, args []string, prepare func(dataDir string), extraEnv ...string) coldStartHookRun {
	return runHookForColdStartWithManaged(t, c, script, args, prepare, false, extraEnv...)
}

func runHookForColdStartWithManaged(t *testing.T, c Connector, script string, args []string, prepare func(dataDir string), managed bool, extraEnv ...string) coldStartHookRun {
	t.Helper()
	// The hooks live in the account's data directory, as an install renders
	// them: a cold start reads that runtime's config and recorded helper.
	home := t.TempDir()
	dataDir := filepath.Join(home, ".defenseclaw")
	hooksDir := filepath.Join(dataDir, "hooks")
	if err := os.MkdirAll(hooksDir, 0o700); err != nil {
		t.Fatal(err)
	}
	apiAddr := freeAPIAddr(t)
	// Bind the endpoint as this account to let these retry tests reach the
	// native transport stub; free and foreign listeners have separate tests.
	listener, err := net.Listen("tcp", apiAddr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	if managed {
		// An explicit managed binary selects standalone, not Secure Client.
		opts := SetupOpts{
			APIAddr: apiAddr, HookAPIToken: "cold-start-scoped-token", HookAPITokenScoped: true,
			ManagedEnterprise: true, ManagedHookBinary: "/usr/bin/defenseclaw-hook",
			HookFailMode: "open", GuardrailMode: "observe",
		}
		err = WriteHookScriptsForConnectorObjectWithOpts(hooksDir, opts, c)
	} else {
		err = writePerUserHooksForTestFailMode(hooksDir, apiAddr, "cold-start-scoped-token", c, extraEnv)
	}
	if err != nil {
		t.Fatalf("write hooks: %v", err)
	}
	hookPath := filepath.Join(hooksDir, script)
	if managed {
		// A managed render posts with curl, not the per-user native helper.
		stubDir := t.TempDir()
		if err := os.WriteFile(filepath.Join(stubDir, "curl"), []byte(coldStartCurlStub), 0o755); err != nil {
			t.Fatal(err)
		}
		bakeHookPathForTest(t, hookPath, stubDir+":/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin")
	}

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
	linkGatewayBinaryToHookDirForTest(t, hooksDir, filepath.Join(binDir, "defenseclaw-gateway"))
	if prepare != nil {
		prepare(dataDir)
	}
	capDir := t.TempDir()
	dropListener := false
	for _, entry := range extraEnv {
		if entry == "DC_COLD_DROP_LISTENER=1" {
			dropListener = true
		}
	}
	if dropListener {
		stop, done := make(chan struct{}), make(chan struct{})
		go func() {
			defer close(done)
			for n := 1; ; n++ {
				marker := filepath.Join(capDir, "drop."+strconv.Itoa(n))
				for {
					select {
					case <-stop:
						return
					default:
					}
					if _, err := os.Stat(marker); err == nil {
						break
					}
					time.Sleep(5 * time.Millisecond)
				}
				_ = listener.Close()
				_ = os.WriteFile(filepath.Join(capDir, "dropped."+strconv.Itoa(n)), nil, 0o600)
				time.Sleep(50 * time.Millisecond)
				for {
					select {
					case <-stop:
						return
					default:
					}
					nextListener, listenErr := net.Listen("tcp", apiAddr)
					if listenErr == nil {
						listener = nextListener
						break
					}
					time.Sleep(5 * time.Millisecond)
				}
			}
		}()
		defer func() { close(stop); <-done }()
	}

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
	// The hook's registered timeout starts with the process, after fixture
	// directories and script snapshots have been written.
	started := time.Now()
	err = cmd.Run()
	return coldStartHookRun{capDir: capDir, dataDir: dataDir, home: home, hooksDir: hooksDir, stdout: stdout.String(), stderr: stderr.String(), err: err, elapsed: time.Since(started)}
}

func TestManagedShellHookNeverColdStartsAGateway(t *testing.T) {
	// A managed hook has no authority to start the machine gateway, even if
	// its administrator selected open for an outage. One refused call is sent.
	run := runHookForColdStartWithManaged(t, NewClaudeCodeConnector(), "claude-code-hook.sh", nil, nil, true,
		"DEFENSECLAW_FAIL_MODE=open", "DC_COLD_FAILS=1000")
	if data, err := os.ReadFile(filepath.Join(run.hooksDir, "claude-code-hook.sh")); err != nil ||
		!strings.Contains(string(data), "_DC_SECURE_CLIENT_HOOK=0") {
		t.Fatalf("hook is not the managed standalone render: %v", err)
	}
	time.Sleep(200 * time.Millisecond)
	if got := readColdStartCapture(t, run.capDir, "gateway.log"); got != "" {
		t.Fatalf("managed hook started the gateway: %q", got)
	}
	if got := strings.TrimSpace(readColdStartCapture(t, run.capDir, "count")); got != "1" {
		t.Fatalf("managed hook sent %q requests, want one", got)
	}
	// Exercise the cold-start helper itself with the managed marker. The
	// end-to-end path returns before calling it, so this pins both guards.
	cmd := exec.Command("bash", "-c", `source "$1"; defenseclaw_gateway_cold_start`, "bash", filepath.Join(run.hooksDir, "_hardening.sh"))
	cmd.Env = append(sanitizedTestEnv(),
		"HOME="+run.home, "DEFENSECLAW_AGENT_HOME="+run.home, "DEFENSECLAW_HOME="+run.dataDir,
		"DEFENSECLAW_MANAGED_HOOK=1", "DEFENSECLAW_GATEWAY_AUTOSTART=1", "DEFENSECLAW_HOOK_SOCKET=", "DC_COLD_CAP="+run.capDir,
		"PATH="+filepath.Join(run.home, ".local", "bin")+":/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin")
	if output, err := cmd.CombinedOutput(); err == nil {
		t.Fatalf("managed cold-start helper returned success: %q", output)
	} else if exit, ok := err.(*exec.ExitError); !ok || exit.ExitCode() != 1 {
		t.Fatalf("managed cold-start helper: %v, output=%q", err, output)
	}
	time.Sleep(200 * time.Millisecond)
	if got := readColdStartCapture(t, run.capDir, "gateway.log"); got != "" {
		t.Fatalf("managed cold-start helper started the gateway: %q", got)
	}
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

// A retry can recover after a refusal. If the listener changes while the
// hook checks it, or the short answer budget expires, the same call blocks.
func TestShellHooksColdStartOrBlockAfterARefusedRequest(t *testing.T) {
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
			run := runHookForColdStart(t, tc.c, tc.script, args, nil, "DC_COLD_DROP_LISTENER=1")
			count := strings.TrimSpace(readColdStartCapture(t, run.capDir, "count"))
			if strings.Contains(run.stderr, "gateway unreachable") {
				attempts, err := strconv.Atoi(count)
				if err != nil || attempts < 1 || attempts > 3 || run.elapsed > 4*time.Second {
					t.Fatalf("refused call blocked outside the retry budget: attempts=%q elapsed=%s", count, run.elapsed)
				}
				if tc.script == "claude-code-hook.sh" {
					_ = failClosedDenyReason(t, run)
				} else if !codexBlockedOrExit2(exitCodeOf(run.err), run.stdout) || !strings.Contains(run.stderr, "this account's gateway") {
					// A per-user Codex block is exit 2 or its own PreToolUse deny on stdout (GAP-0949, GAP-1088).
					t.Fatalf("Codex refusal did not fail closed: exit=%d stdout=%q stderr=%q", exitCodeOf(run.err), run.stdout, run.stderr)
				}
				if log := readColdStartCapture(t, run.capDir, "gateway.log"); strings.Count(log, "start --hook-cold-start") > 1 {
					t.Fatalf("refused call started the gateway more than once: %q", log)
				}
				return
			}
			if run.err != nil {
				t.Fatalf("hook failed: %v\nstderr=%s", run.err, run.stderr)
			}
			if count != "2" {
				t.Fatalf("native post ran %q times, want 2 (refused, then sent again)", count)
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
	// With a listener still bound, a failed native post is ambiguous. The
	// hook blocks without retrying credentials to a possibly changed peer.
	const waited = "this account's gateway is not running; run `defenseclaw-gateway start`"
	// An install or upgrade stops the gateway like an operator does and
	// starts it again when it is done: a restart, not a stop (GAP-0140).
	const installing = "DefenseClaw is being installed or upgraded for this account and its gateway starts again when that is done"
	cases := map[string]struct {
		prepare func(string)
		env     []string
		hint    string
		closed  bool
	}{
		// The hook names the way back (SWEEP-16): an explicit stop is never
		// undone by a hook, so the user has to start the gateway.
		"stopped with defenseclaw-gateway stop": {prepare: func(dataDir string) {
			_ = os.WriteFile(filepath.Join(dataDir, "gateway.stopped"), []byte("stopped\n"), 0o600)
		}, hint: "stopped with `defenseclaw-gateway stop`; run `defenseclaw-gateway start` to resume protection"},
		// The install window is not an outage: an open fail mode does not let
		// the call through unchecked (GAP-0649).
		"install in progress": {prepare: func(dataDir string) {
			_ = os.Mkdir(filepath.Join(dataDir, ".install.lock"), 0o700)
		}, hint: installing, closed: true},
		"stopped by an upgrade in progress": {prepare: func(dataDir string) {
			_ = os.Mkdir(filepath.Join(dataDir, ".install.lock"), 0o700)
			_ = os.WriteFile(filepath.Join(dataDir, "gateway.stopped"), []byte("stopped\n"), 0o600)
		}, hint: installing, closed: true},
		"install with inherited socket marker": {prepare: func(dataDir string) {
			_ = os.Mkdir(filepath.Join(dataDir, ".install.lock"), 0o700)
		}, env: []string{"DEFENSECLAW_HOOK_SOCKET=/tmp/inherited.sock"}, hint: installing, closed: true},
		"install with inherited managed marker": {prepare: func(dataDir string) {
			_ = os.Mkdir(filepath.Join(dataDir, ".install.lock"), 0o700)
		}, env: []string{"DEFENSECLAW_MANAGED_HOOK=1"}, hint: installing, closed: true},
		"no configuration": {prepare: func(dataDir string) {
			_ = os.Remove(filepath.Join(dataDir, "config.yaml"))
		}, hint: waited},
		"autostart off": {env: []string{"DEFENSECLAW_GATEWAY_AUTOSTART=0"}, hint: waited},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			// An old per-user open setting stays closed, including during install.
			env := append([]string{"DEFENSECLAW_FAIL_MODE=open", "DC_COLD_FAILS=1000"}, tc.env...)
			run := runHookForColdStart(t, NewClaudeCodeConnector(), "claude-code-hook.sh", nil, tc.prepare, env...)
			time.Sleep(200 * time.Millisecond) // a background start would have logged by now
			if log := readColdStartCapture(t, run.capDir, "gateway.log"); log != "" {
				t.Fatalf("hook started the gateway: %q", log)
			}
			count, _ := strconv.Atoi(strings.TrimSpace(readColdStartCapture(t, run.capDir, "count")))
			if count != 1 {
				t.Fatalf("native post ran %d times, want one refused attempt with no send to a changed peer", count)
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
			if !strings.Contains(run.stdout, `"permissionDecision":"deny"`) || strings.Contains(run.stdout, "systemMessage") {
				t.Errorf("stdout = %q, want a per-user native deny", run.stdout)
			}
			if tc.closed {
				reason := failClosedDenyReason(t, run)
				if !strings.Contains(run.stdout, "is being installed or upgraded for this account") ||
					!strings.Contains(run.stdout, "defenseclaw-gateway status") ||
					!strings.Contains(reason, "run the installer again") ||
					strings.Contains(reason, "defenseclaw-gateway start") ||
					strings.Contains(run.stdout, "stopped with") {
					t.Errorf("stdout = %q, want the install-time native deny, its recovery step and status", run.stdout)
				}
			}
		})
	}
}

// A frozen or hung gateway keeps its listener, so the request times out
// (native post exit 28) while gateway.pid names a live process. The line says so once,
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
		t.Fatalf("native post ran %q times, want 1: a gateway that accepted the call keeps it", got)
	}

	open := runHookForColdStart(t, NewClaudeCodeConnector(), "claude-code-hook.sh", nil, alive,
		"DEFENSECLAW_FAIL_MODE=open", "DC_COLD_FIRST_RC=28")
	if reason := failClosedDenyReason(t, open); !strings.Contains(reason, "the gateway is running but did not answer") {
		t.Errorf("per-user open request yielded %q, want a closed deny naming the hung gateway", reason)
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

// An old per-user open setting cannot allow Codex past a stopped gateway.
func TestCodexShellHookShowsTheStartStepWhenTheGatewayWasStopped(t *testing.T) {
	run := runHookForColdStart(t, NewCodexConnector(), "codex-hook.sh",
		codexBoundShellHookArgsForTest(t, "codex-hook.sh", "PreToolUse")[1:],
		func(dataDir string) {
			_ = os.WriteFile(filepath.Join(dataDir, "gateway.stopped"), []byte("stopped\n"), 0o600)
		}, "DEFENSECLAW_FAIL_MODE=open")
	// A per-user Codex block is Codex's own PreToolUse deny on stdout (GAP-0949).
	if code := exitCodeOf(run.err); !codexBlockAnswer("PreToolUse", code, run.stdout) || !strings.Contains(run.stderr, "stopped with `defenseclaw-gateway stop`") {
		t.Errorf("per-user open request: exit %d stdout=%q stderr=%q, want a closed block naming the stop", code, run.stdout, run.stderr)
	}
}

// GAP-0094, GAP-0102, GAP-0107: only a refused connection is retried. A
// dropped or cut-off answer may have processed the call and must not become
// a later outage allow, even if the listener disappears. A heavily loaded
// host may spend the retry budget starting the hook and helper; it blocks.
func TestShellHookOnlyRetriesRefusedConnections(t *testing.T) {
	for _, tc := range []struct {
		name, rc string
	}{
		// The native helper reports a reset or empty reply before any status
		// as its outage status 7 (hookexec.PerUserPostOutage); any other
		// helper failure came after its peer check and is final (T12b loop 2).
		{name: "refused", rc: "7"},
	} {
		for _, hook := range []struct {
			c      Connector
			script string
		}{
			{NewClaudeCodeConnector(), "claude-code-hook.sh"},
			{NewCodexConnector(), "codex-hook.sh"},
		} {
			t.Run(tc.name+"/"+hook.script, func(t *testing.T) {
				var args []string
				if hook.script == "codex-hook.sh" {
					args = codexBoundShellHookArgsForTest(t, hook.script, "PreToolUse")[1:]
				}
				failMode := "closed"
				if tc.rc != "7" {
					failMode = "open"
				}
				run := runHookForColdStart(t, hook.c, hook.script, args, nil,
					"DEFENSECLAW_FAIL_MODE="+failMode, "DC_COLD_OUTAGE_MODE=open", "DC_COLD_FAILS=2", "DC_COLD_FIRST_RC="+tc.rc, "DC_COLD_DROP_LISTENER=1")
				if run.elapsed > 4*time.Second {
					t.Fatalf("the call took %s", run.elapsed)
				}
				count := strings.TrimSpace(readColdStartCapture(t, run.capDir, "count"))
				if count != "1" && count != "2" && count != "3" {
					t.Fatalf("native post ran %q times, want 1-3 bounded attempts", count)
				}
				if tc.rc != "7" && count != "1" {
					t.Fatalf("classified non-outage was retried %s times", count)
				}
				blockedByOutage := strings.Contains(run.stderr, "gateway unreachable")
				if blockedByOutage {
					if !strings.Contains(run.stderr, "this account's gateway") {
						t.Fatalf("budget expired without naming the gateway: %s", run.stderr)
					}
					if hook.script == "claude-code-hook.sh" {
						_ = failClosedDenyReason(t, run)
					} else if !codexBlockedOrExit2(exitCodeOf(run.err), run.stdout) {
						// Exit 2 or Codex's own PreToolUse deny on stdout (GAP-0949, GAP-1088).
						t.Fatalf("Codex budget expiry did not block: err=%v stdout=%q", run.err, run.stdout)
					}
				} else if run.err != nil || strings.Contains(run.stdout, "deny") || count != "3" {
					t.Fatalf("gateway answer was not the third attempt's allow: err=%v stdout=%q stderr=%q count=%q", run.err, run.stdout, run.stderr, count)
				}
				log := strings.TrimSpace(readColdStartCapture(t, run.capDir, "gateway.log"))
				if tc.rc == "7" {
					log = strings.TrimSpace(waitColdStartCapture(t, run.capDir, "gateway.log"))
				}
				starts := strings.Count(log, "start --hook-cold-start")
				wantStarts := 0
				if tc.rc == "7" && !blockedByOutage {
					wantStarts = 1
				}
				if starts > 1 || (!blockedByOutage && starts != wantStarts) || (tc.rc != "7" && starts != 0) {
					t.Fatalf("gateway starts = %q, want only a refused connection to start it", log)
				}
			})
		}
	}
}

// A restart or outage longer than the budget blocks the call within about
// 3 seconds and names this account's unavailable gateway.
func TestShellHookBlocksWhenTheRestartOutlastsTheBudget(t *testing.T) {
	for _, rc := range []string{"7", "56"} {
		t.Run("claude-code/"+rc, func(t *testing.T) {
			run := runHookForColdStart(t, NewClaudeCodeConnector(), "claude-code-hook.sh", nil, nil,
				"DEFENSECLAW_FAIL_MODE=closed", "DC_COLD_FAILS=1000", "DC_COLD_FIRST_RC="+rc, "DC_COLD_DROP_LISTENER=1")
			assertBlockedWithinTheRestartBudget(t, run)
			if log := waitColdStartCapture(t, run.capDir, "gateway.log"); strings.Count(log, "start --hook-cold-start") > 1 {
				t.Fatalf("the refused call started the gateway more than once: %q", log)
			}
			if reason := failClosedDenyReason(t, run); !strings.Contains(reason, "this account's gateway is not running") &&
				!strings.Contains(reason, "restarting or not running") {
				t.Fatalf("deny reason = %q, want this account's unavailable gateway named", reason)
			}
		})
		t.Run("codex/"+rc, func(t *testing.T) {
			run := runHookForColdStart(t, NewCodexConnector(), "codex-hook.sh",
				codexBoundShellHookArgsForTest(t, "codex-hook.sh", "PreToolUse")[1:], nil,
				"DEFENSECLAW_FAIL_MODE=closed", "DC_COLD_FAILS=1000", "DC_COLD_FIRST_RC="+rc, "DC_COLD_DROP_LISTENER=1")
			assertBlockedWithinTheRestartBudget(t, run)
			if log := waitColdStartCapture(t, run.capDir, "gateway.log"); strings.Count(log, "start --hook-cold-start") > 1 {
				t.Fatalf("the refused call started the gateway more than once: %q", log)
			}
			if code := exitCodeOf(run.err); !codexBlockAnswer("PreToolUse", code, run.stdout) || !strings.Contains(run.stderr, "blocking codex tool") ||
				(!strings.Contains(run.stderr, "this account's gateway is not running") &&
					!strings.Contains(run.stderr, "restarting or not running")) {
				t.Fatalf("exit %d stderr %q, want a block naming this account's unavailable gateway", code, run.stderr)
			}
		})
	}
}

func assertBlockedWithinTheRestartBudget(t *testing.T, run coldStartHookRun) {
	t.Helper()
	// The call waited for the restart: bash 3.2 (macOS) counts whole
	// seconds, so the end can come up to a second early there.
	if run.elapsed < 1500*time.Millisecond {
		t.Fatalf("the call was blocked after %s, want about 3 s", run.elapsed)
	}
	// The 3-second budget is the hook's retry window: its last try starts
	// inside it, counted from its first. Bash start-up before the first try
	// and the block answer after the last are not part of it, and the full
	// race suite stretches both on a loaded host (GAP-0938), so the window
	// is read from the gateway stub's arrival times. A hook that hangs still
	// fails on the wall clock.
	if window, ok := coldStartTryWindow(t, run.capDir); ok {
		if window > 4500*time.Millisecond {
			t.Fatalf("the retries ran for %s, want about 3 s (call blocked after %s)", window, run.elapsed)
		}
		if run.elapsed > 30*time.Second {
			t.Fatalf("the call was blocked after %s, want about 3 s of retries", run.elapsed)
		}
	} else if run.elapsed > 4500*time.Millisecond {
		t.Fatalf("the call was blocked after %s, want about 3 s", run.elapsed)
	}
}

// coldStartTryWindow is the time from the stub's first gateway try to its
// last; false without two arrival times (no nanosecond clock on the host).
func coldStartTryWindow(t *testing.T, capDir string) (time.Duration, bool) {
	t.Helper()
	var first, last int64
	n := 0
	for _, line := range strings.Fields(readColdStartCapture(t, capDir, "tries")) {
		v, err := strconv.ParseInt(line, 10, 64)
		if err != nil {
			continue
		}
		if n == 0 || v < first {
			first = v
		}
		if n == 0 || v > last {
			last = v
		}
		n++
	}
	if n < 2 {
		return 0, false
	}
	return time.Duration(last - first), true
}

// codexBlockedOrExit2 is a closed Codex PreToolUse answer: exit 2, or Codex own
// PreToolUse deny on stdout (GAP-0949).
func codexBlockedOrExit2(code int, stdout string) bool {
	return codexBlockAnswer("PreToolUse", code, stdout) || (code == 2 && stdout == "")
}
