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

func TestManagedHermesAnswersLifecycleBeforeForeignGuardWait(t *testing.T) {
	invoke := hookArgvConnectorCase(t, "hermes")
	data := t.TempDir()
	hooks := filepath.Join(data, "hooks")
	guardCalls := filepath.Join(data, "foreign-guard-called")
	guard := filepath.Join(data, "defenseclaw-hook")
	guardScript := "#!/bin/sh\n: > '" + guardCalls + "'\nsleep 2\nprintf '{\"deny\":false}\\n'\n"
	if err := os.WriteFile(guard, []byte(guardScript), 0o700); err != nil {
		t.Fatal(err)
	}
	opts := SetupOpts{
		DataDir: data, APIAddr: "127.0.0.1:1", APIToken: "test-token",
		HookFailMode: "closed", GuardrailMode: "action", ManagedEnterprise: true,
		ManagedHookSocket:      filepath.Join(data, "hook.sock"),
		ForeignHookGuardBinary: guard,
	}
	if err := WriteHookScriptsForConnectorObjectWithOpts(hooks, opts, NewHermesConnector()); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(data, "lifecycle.active")
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
	ctx, cancel := context.WithTimeout(context.Background(), 2500*time.Millisecond)
	defer cancel()
	cmd := exec.CommandContext(ctx, "bash", append([]string{filepath.Join(hooks, invoke.script)}, invoke.args...)...)
	cmd.Stdin = strings.NewReader(invoke.stdin)
	cmd.Env = append(sanitizedTestEnv(), "HOME="+data, "DEFENSECLAW_HOME="+data)
	cmd.Env = append(cmd.Env, invoke.env...)
	started := time.Now()
	output, err := cmd.CombinedOutput()
	if err != nil || time.Since(started) > time.Second || !bytes.Contains(output, []byte(`"action":"block"`)) ||
		!bytes.Contains(output, []byte("installed or upgraded")) {
		t.Fatalf("managed Hermes lifecycle answer took %s: %q (%v)", time.Since(started), output, err)
	}
	if _, err := os.Stat(guardCalls); !os.IsNotExist(err) {
		t.Fatalf("foreign guard ran during the closed lifecycle: %v", err)
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
