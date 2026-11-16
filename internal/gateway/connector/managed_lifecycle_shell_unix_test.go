// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package connector

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// GAP-1676: a no-op ensure holds the lifecycle marker while the gateway
// keeps answering. The standalone Hermes hook answered every tool call with
// the lifecycle block while the marker existed, before it asked the guard or
// the gateway, so Hermes blocked benign calls that the native managed hooks
// allowed in the same window. Like the native hook, it now gives the
// lifecycle answer only when the gateway could not answer (no check answer,
// or a deny the check marked retryable); an allow goes on to the gateway and
// a confirmed deny keeps its own block.
func TestManagedHermesLifecycleMarkerBlocksOnlyWhatTheGatewayCannotAnswer(t *testing.T) {
	curlPath, err := exec.LookPath("curl")
	if err != nil {
		t.Skip("curl is required to run shell hooks")
	}
	f := newHookSocketFixture(t, "dclm", nil)
	guard := filepath.Join(f.root, "bin", "defenseclaw-hook")
	if err := os.Mkdir(filepath.Dir(guard), 0o755); err != nil {
		t.Fatal(err)
	}
	answerPath := filepath.Join(f.root, "answer")
	guardScript := "#!/bin/bash\n" +
		"[ \"$*\" = \"hook session-facts\" ] && exit 0\n" +
		"cat > /dev/null\n" +
		"cat " + shellSingleQuoteForTest(answerPath) + " 2>/dev/null\n"
	if err := os.WriteFile(guard, []byte(guardScript), 0o755); err != nil {
		t.Fatal(err)
	}
	agentHome := filepath.Join(f.root, "home")
	dataDir := filepath.Join(agentHome, ".defenseclaw")
	hooks := filepath.Join(dataDir, "hooks")
	opts := SetupOpts{
		DataDir: dataDir, APIAddr: "127.0.0.1:1", APIToken: "tok",
		HookFailMode: "closed", GuardrailMode: "action", ManagedEnterprise: true,
		ManagedHookSocket:      f.socket,
		ManagedServiceUID:      os.Getuid(),
		ForeignHookGuardBinary: guard,
	}
	if err := WriteHookScriptsForConnectorObjectWithOpts(hooks, opts, NewHermesConnector()); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(f.root, "lifecycle.active")
	hardening := filepath.Join(hooks, "_hardening.sh")
	script, err := os.ReadFile(hardening)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(hardening, bytes.ReplaceAll(script, []byte(shellLifecycleMarkers), []byte(marker)), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(marker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	hookPath := filepath.Join(hooks, "hermes-hook.sh")
	bakeHookPathForTest(t, hookPath, filepath.Dir(curlPath)+":/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin")
	requests := func() int {
		paths, _, _ := f.gateway.recorded()
		return len(paths)
	}
	run := func(answer string) (string, string) {
		t.Helper()
		if err := os.WriteFile(answerPath, []byte(answer), 0o644); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, "bash", hookPath)
		cmd.Env = append(os.Environ(), "HOME="+agentHome)
		cmd.Stdin = strings.NewReader(`{"hook_event_name":"pre_tool_call","session_id":"s-1","tool_name":"terminal","tool_input":{"command":"echo marker"}}`)
		var stdout, stderr bytes.Buffer
		cmd.Stdout, cmd.Stderr = &stdout, &stderr
		if err := cmd.Run(); err != nil {
			t.Fatalf("run hook: %v (stderr %q)", err, stderr.String())
		}
		return strings.TrimSpace(stdout.String()), stderr.String()
	}
	const lifecycle = "being installed or upgraded"

	// The check allows: the gateway decides, as for the native hooks.
	if stdout, stderr := run(`{"deny":false}` + "\n"); strings.Contains(stdout, lifecycle) || !strings.Contains(stdout, "hook-socket") || requests() != 1 {
		t.Fatalf("allowed check while the marker is held: stdout=%q stderr=%q requests=%d, want the gateway's answer", stdout, stderr, requests())
	}
	// The gateway could not answer the check: the lifecycle answer.
	for _, answer := range []string{
		`{"deny":true,"reason":"enterprise_managed_gateway_not_running","retryable":true}` + "\n",
		"",
	} {
		if stdout, stderr := run(answer); !strings.HasPrefix(stdout, `{"action":"block"`) || !strings.Contains(stdout, lifecycle) || requests() != 1 {
			t.Fatalf("check %q while the marker is held: stdout=%q stderr=%q requests=%d, want the lifecycle block", answer, stdout, stderr, requests())
		}
	}
	// A confirmed deny keeps its own block.
	block := `{"action":"block","message":"DefenseClaw blocked this tool call: the user file defines a hook. (enterprise_foreign_hook_blocked)"}`
	if stdout, stderr := run(`{"deny":true,"reason":"enterprise_foreign_hook_blocked: x","hook_output":` + block + `}` + "\n"); stdout != block {
		t.Fatalf("confirmed deny while the marker is held: stdout=%q stderr=%q, want the guard's block", stdout, stderr)
	}
}

// shellLifecycleMarkers is the marker list of _hardening.sh, the Linux and
// macOS paths of the lifecycle run marker.
const shellLifecycleMarkers = "/run/defenseclaw-lifecycle.active /var/run/defenseclaw-lifecycle.active"

// The shell hooks look for the lifecycle run marker at the layout's paths:
// the lifecycle writes it there (managed.StandaloneLayout).
func TestShellHooksReadTheLayoutsLifecycleMarker(t *testing.T) {
	script, err := os.ReadFile(filepath.Join("hooks", "_hardening.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(script), "for marker in "+shellLifecycleMarkers+"; do") {
		t.Fatal("_hardening.sh does not list the lifecycle markers")
	}
	for _, goos := range []string{"linux", "darwin"} {
		layout, err := managed.StandaloneLayoutFor(goos)
		if err != nil || layout.LifecycleMarkerPath == "" ||
			!strings.Contains(" "+shellLifecycleMarkers+" ", " "+layout.LifecycleMarkerPath+" ") {
			t.Fatalf("%s lifecycle marker %q (%v) is not in the shell hooks' list", goos, layout.LifecycleMarkerPath, err)
		}
	}
}

// GAP-1074: a managed Linux or macOS shell hook whose administrator chose
// open let a call run while the lifecycle stopped or restarted the gateway
// (an upgrade, a repair, a configuration change), since the managed hooks
// read no install state at all. While the lifecycle's run marker exists,
// every managed shell hook answers its gateway outage closed; without it
// the administrator's open applies (control; a managed Copilot CLI hook is
// closed on an outage anyway), and a per-user hook answers as it does
// without the marker.
func TestManagedShellHooksCloseWhileTheLifecycleRuns(t *testing.T) {
	if _, err := exec.LookPath("curl"); err != nil {
		t.Skip("curl unavailable")
	}
	for _, managedHook := range []bool{true, false} {
		for _, conn := range hookArgvShellConnectors {
			name := conn.Name() + "/managed"
			if !managedHook {
				name = conn.Name() + "/per-user (control)"
			}
			t.Run(name, func(t *testing.T) {
				invoke := hookArgvConnectorCase(t, conn.Name())
				data := t.TempDir()
				hooks := filepath.Join(data, "hooks")
				opts := SetupOpts{
					DataDir: data, APIAddr: "127.0.0.1:1", APIToken: "test-token",
					HookFailMode: "open", GuardrailMode: "action",
				}
				if managedHook {
					opts.ManagedEnterprise = true
					opts.ManagedHookBinary = "/usr/local/libexec/defenseclaw-hook"
				}
				if err := WriteHookScriptsForConnectorObjectWithOpts(hooks, opts, conn); err != nil {
					t.Fatal(err)
				}
				// A folder name without shell syntax: the marker list is a
				// plain word list.
				markerDir, err := os.MkdirTemp("", "dc-lifecycle")
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = os.RemoveAll(markerDir) })
				marker := filepath.Join(markerDir, "defenseclaw-lifecycle.active")
				hardening := filepath.Join(hooks, "_hardening.sh")
				info, err := os.Stat(hardening)
				if err != nil {
					t.Fatal(err)
				}
				script, err := os.ReadFile(hardening)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Contains(script, []byte(shellLifecycleMarkers)) {
					t.Fatal("rendered _hardening.sh does not list the lifecycle markers")
				}
				if err := os.WriteFile(hardening, bytes.ReplaceAll(script, []byte(shellLifecycleMarkers), []byte(marker)), info.Mode().Perm()); err != nil {
					t.Fatal(err)
				}
				answer := func() (bool, string) {
					cmd := exec.Command("bash", append([]string{filepath.Join(hooks, invoke.script)}, invoke.args...)...)
					cmd.Stdin = strings.NewReader(invoke.stdin)
					cmd.Env = append(sanitizedTestEnv(), "HOME="+data, "DEFENSECLAW_HOME="+data)
					cmd.Env = append(cmd.Env, invoke.env...)
					var stdout, stderr bytes.Buffer
					cmd.Stdout, cmd.Stderr = &stdout, &stderr
					err := cmd.Run()
					blocks := err != nil || strings.Contains(stdout.String(), `"deny"`) || strings.Contains(stdout.String(), `"block"`)
					return blocks, "err=" + strings.TrimSpace(func() string {
						if err == nil {
							return "<nil>"
						}
						return err.Error()
					}()) + " stdout=" + stdout.String() + " stderr=" + stderr.String()
				}
				idle, got := answer()
				if managedHook && idle && conn.Name() != "copilot" {
					t.Fatalf("no lifecycle run, open: %s, want the call to run (control)", got)
				}
				if err := os.WriteFile(marker, []byte("1\n"), 0o644); err != nil {
					t.Fatal(err)
				}
				want := idle
				if managedHook {
					want = true
				}
				if blocks, got := answer(); blocks != want {
					t.Fatalf("lifecycle running, open: %s; blocks=%v, want %v", got, blocks, want)
				}
			})
		}
	}
}
