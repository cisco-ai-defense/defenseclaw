// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package connector

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

var managedHookTestToken = strings.Repeat("0123456789abcdef", 4)

type managedHookRun struct {
	exitCode int
	stdout   string
	stderr   string
	diag     string
}

var managedHookTestScripts = map[string]string{
	"claudecode": "claude-code-hook.sh",
	"codex":      "codex-hook.sh",
	"cursor":     "cursor-hook.sh",
}

// managedHookTestArgs are the arguments Setup binds into a registered hook
// command: the Codex hook refuses a call without its event and contract.
var managedHookTestArgs = map[string][]string{
	"codex-hook.sh": {"--event", "PreToolUse", "--hook-contract", "codex-hooks-v4"},
}

// forceManagedShellGuard renders the macOS managed shell guard on any host so
// the bash behavior is exercised wherever the tests run.
func forceManagedShellGuard(t *testing.T) {
	t.Helper()
	previous := managedShellGuardGOOS
	managedShellGuardGOOS = "darwin"
	t.Cleanup(func() { managedShellGuardGOOS = previous })
}

func renderManagedHookForTest(t *testing.T, connectorName, apiAddr, failMode string) (string, string) {
	t.Helper()
	forceManagedShellGuard(t)
	dataDir := filepath.Join(t.TempDir(), ".defenseclaw")
	hookDir := filepath.Join(dataDir, "hooks")
	script := managedHookTestScripts[connectorName]
	// The guard is a Secure Client render: a verified Secure Client host
	// with its delivery contract.
	if err := writeHookScriptsCommonWithTransport(
		hookDir, apiAddr, managedHookTestToken, failMode, HookFailModeSourceConfig,
		[]string{script}, true, connectorName, true, "", "", true, true,
	); err != nil {
		t.Fatalf("render managed %s hook: %v", connectorName, err)
	}
	return dataDir, filepath.Join(hookDir, script)
}

func runManagedHookForTest(t *testing.T, script string, payload string, extraEnv ...string) managedHookRun {
	t.Helper()
	bash := "/bin/bash"
	if _, err := os.Stat(bash); err != nil {
		t.Skip("bash is not available")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bash, append([]string{script}, managedHookTestArgs[filepath.Base(script)]...)...)
	cmd.Stdin = strings.NewReader(payload)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	cmd.Env = append([]string{
		"HOME=" + t.TempDir(),
		"PATH=/usr/bin:/bin",
		"LANG=C",
	}, extraEnv...)
	err := cmd.Run()
	run := managedHookRun{stdout: stdout.String(), stderr: stderr.String()}
	var exitErr *exec.ExitError
	switch {
	case err == nil:
	case errors.As(err, &exitErr):
		run.exitCode = exitErr.ExitCode()
	default:
		t.Fatalf("run %s: %v", script, err)
	}
	dataDir := filepath.Dir(filepath.Dir(script))
	if diag, err := os.ReadFile(filepath.Join(dataDir, "logs", "hook-diagnostics.log")); err == nil {
		run.diag = string(diag)
	}
	return run
}

func assertManagedHookFailModeOutcome(t *testing.T, connectorName, failMode string, run managedHookRun) {
	t.Helper()
	switch {
	case failMode == "open":
		if run.exitCode != 0 {
			t.Fatalf("open %s exit = %d, want 0 (stderr %q, diag %q)", connectorName, run.exitCode, run.stderr, run.diag)
		}
		if run.stderr != "" {
			t.Fatalf("open %s wrote to the agent's stderr: %q", connectorName, run.stderr)
		}
		if connectorName == "cursor" && strings.Contains(run.stdout, `"permission":"deny"`) {
			t.Fatalf("open cursor stdout = %q, want no deny", run.stdout)
		}
	case connectorName == "cursor":
		if run.exitCode != 2 {
			t.Fatalf("closed cursor exit = %d, want 2 (diag %q)", run.exitCode, run.diag)
		}
		if run.stderr != "" {
			t.Fatalf("closed cursor wrote to the agent's stderr: %q", run.stderr)
		}
		if strings.Contains(run.stdout, `"permission":"allow"`) {
			t.Fatalf("closed cursor stdout = %q, want no allow", run.stdout)
		}
	default:
		if run.exitCode != 2 {
			t.Fatalf("closed %s exit = %d, want 2 (diag %q)", connectorName, run.exitCode, run.diag)
		}
		if run.stderr != managedHookBlockSentence+"\n" {
			t.Fatalf("closed %s stderr = %q, want only the block sentence", connectorName, run.stderr)
		}
	}
}

// An unexpected shell failure in a managed hook follows the configured fail
// mode instead of bash's exit status 1, writes nothing to the agent's stderr
// except the protocol block reason, and records the cause in the per-user log.
func TestManagedShellHookUnexpectedFailureFollowsFailMode(t *testing.T) {
	failures := map[string]func(t *testing.T, hookDir string){
		"helper missing": func(t *testing.T, hookDir string) {
			if err := os.Remove(filepath.Join(hookDir, "_hardening.sh")); err != nil {
				t.Fatal(err)
			}
		},
		"helper exits 1": func(t *testing.T, hookDir string) {
			if err := os.WriteFile(filepath.Join(hookDir, "_hardening.sh"), []byte("echo boom >&2\nexit 1\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"helper has an unbound variable": func(t *testing.T, hookDir string) {
			if err := os.WriteFile(filepath.Join(hookDir, "_hardening.sh"), []byte("echo \"$_DC_TEST_UNSET_VARIABLE\"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		},
	}
	for connectorName := range managedHookTestScripts {
		for _, failMode := range []string{"open", "closed"} {
			for failureName, inject := range failures {
				t.Run(connectorName+"/"+failMode+"/"+failureName, func(t *testing.T) {
					_, script := renderManagedHookForTest(t, connectorName, "127.0.0.1:1", failMode)
					inject(t, filepath.Dir(script))
					run := runManagedHookForTest(t, script, `{"hook_event_name":"PreToolUse"}`)
					assertManagedHookFailModeOutcome(t, connectorName, failMode, run)
					if run.diag == "" {
						t.Fatalf("no diagnostics recorded in the per-user log")
					}
				})
			}
		}
	}
}

// A gateway outage is a delivery failure: it follows the fail mode and the
// fail-open warning goes to the per-user log, not the agent's stderr.
func TestManagedShellHookUnreachableGatewayKeepsAgentStderrClean(t *testing.T) {
	if _, err := os.Stat("/usr/bin/curl"); err != nil {
		t.Skip("curl is not available")
	}
	for connectorName := range managedHookTestScripts {
		for _, failMode := range []string{"open", "closed"} {
			t.Run(connectorName+"/"+failMode, func(t *testing.T) {
				_, script := renderManagedHookForTest(t, connectorName, "127.0.0.1:1", failMode)
				run := runManagedHookForTest(t, script, `{"hook_event_name":"PreToolUse"}`)
				assertManagedHookFailModeOutcome(t, connectorName, failMode, run)
			})
		}
	}
}

// Managed hooks ignore the payload cap from the agent's environment, so
// exporting DEFENSECLAW_HOOK_MAX_BODY=1 cannot turn every event into an
// oversized, fail-open one.
func TestManagedShellHookIgnoresMaxBodyEnvironment(t *testing.T) {
	if _, err := os.Stat("/usr/bin/curl"); err != nil {
		t.Skip("curl is not available")
	}
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"action":"allow"}`))
	}))
	defer server.Close()
	apiAddr := strings.TrimPrefix(server.URL, "http://")
	for connectorName := range managedHookTestScripts {
		t.Run(connectorName, func(t *testing.T) {
			before := requests.Load()
			_, script := renderManagedHookForTest(t, connectorName, apiAddr, "open")
			run := runManagedHookForTest(t, script, `{"hook_event_name":"PreToolUse","prompt":"hello"}`,
				"DEFENSECLAW_HOOK_MAX_BODY=1", "DEFENSECLAW_FAIL_MODE=open")
			if requests.Load() == before {
				t.Fatalf("payload never reached the gateway; the environment cap was honored (exit %d, diag %q)", run.exitCode, run.diag)
			}
			if run.stderr != "" {
				t.Fatalf("agent stderr = %q, want empty", run.stderr)
			}
		})
	}
}

// Unmanaged hooks keep their existing behavior: diagnostics on stderr and the
// environment cap honored (a per-user hook refuses the oversized payload).
func TestUnmanagedShellHookKeepsEnvironmentCap(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), ".defenseclaw")
	hookDir := filepath.Join(dataDir, "hooks")
	if err := writeHookScriptsCommonWithOptions(
		hookDir, "127.0.0.1:1", managedHookTestToken, "open",
		[]string{"claude-code-hook.sh"}, false, "claudecode", true,
	); err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(hookDir, "claude-code-hook.sh")
	data, err := os.ReadFile(script)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "_dc_managed_fail") {
		t.Fatalf("unmanaged hook carries the managed prologue")
	}
	run := runManagedHookForTest(t, script, `{"hook_event_name":"PreToolUse","prompt":"hello"}`,
		"DEFENSECLAW_HOME="+dataDir, "DEFENSECLAW_HOOK_MAX_BODY=1")
	if !strings.Contains(run.stderr, "oversized") {
		t.Fatalf("unmanaged hook exit=%d stderr=%q, want the oversized warning on stderr", run.exitCode, run.stderr)
	}
}

// A policy block keeps its own reason on the agent's stderr; only failures
// without a policy reason use the fixed block sentence.
func TestManagedClaudeHookPolicyBlockKeepsReason(t *testing.T) {
	if _, err := os.Stat("/usr/bin/curl"); err != nil {
		t.Skip("curl is not available")
	}
	if _, err := os.Stat("/usr/bin/jq"); err != nil {
		if _, err := os.Stat("/usr/local/bin/jq"); err != nil {
			t.Skip("jq is not available on the hardened hook PATH")
		}
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"action":"block","reason":"policy says no"}`))
	}))
	defer server.Close()
	_, script := renderManagedHookForTest(t, "claudecode", strings.TrimPrefix(server.URL, "http://"), "open")
	run := runManagedHookForTest(t, script, `{"hook_event_name":"PreToolUse"}`)
	if run.exitCode != 2 || run.stderr != "policy says no\n" {
		t.Fatalf("exit=%d stderr=%q, want 2 and the policy reason", run.exitCode, run.stderr)
	}
}
