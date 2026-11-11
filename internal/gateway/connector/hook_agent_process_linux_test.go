// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"bufio"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

func TestAccountAgentProcessMayRunIgnoresManagementArguments(t *testing.T) {
	agent := "dcagentprobe-" + strconv.Itoa(os.Getpid())
	dataDir := t.TempDir()
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 unavailable")
	}
	// The removal command names the connector, but is not the agent process.
	managementScript := filepath.Join(t.TempDir(), "defenseclaw")
	if err := os.WriteFile(managementScript, []byte("import time\ntime.sleep(30)\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	management := exec.Command(python, managementScript, "setup", "remove", agent)
	if err := management.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = management.Process.Kill(); _ = management.Wait() })
	if accountAgentProcessMayRun(dataDir, agent) {
		t.Fatal("management command was counted as a running agent")
	}

	sleeper := testenv.NativeSleep(t)
	agentImage := filepath.Join(t.TempDir(), agent)
	if err := os.Symlink(sleeper, agentImage); err != nil {
		t.Fatal(err)
	}
	running := exec.Command(agentImage, "30")
	if err := running.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = running.Process.Kill(); _ = running.Wait() })
	if !accountAgentProcessMayRun(dataDir, agent) {
		t.Fatal("running agent process was missed")
	}
}

func TestRemovePerUserConnectorHookFilesAfterWrappedRemoval(t *testing.T) {
	for _, name := range []string{"devin", "kiro"} {
		for _, running := range []bool{false, true} {
			t.Run(name+"/running="+strconv.FormatBool(running), func(t *testing.T) {
				t.Setenv("HOME", t.TempDir())
				t.Setenv("XDG_CONFIG_HOME", t.TempDir())
				dataDir := t.TempDir()
				opts := SetupOpts{DataDir: dataDir, ConfigHome: t.TempDir()}
				removed, ok := NewDefaultRegistry().Get(name)
				if !ok {
					t.Fatal("connector missing")
				}
				hookDir := filepath.Join(dataDir, "hooks")
				if err := WriteHookScriptsForConnectorObjectWithOpts(hookDir, opts, removed); err != nil {
					t.Fatal(err)
				}
				if err := removed.Teardown(context.Background(), opts); err != nil {
					t.Fatal(err)
				}
				owner := removed.(HookScriptOwner)
				script := filepath.Join(hookDir, owner.HookScriptNames(opts)[0])
				if body, err := os.ReadFile(script); err != nil || !strings.Contains(string(body), "(disabled tombstone)") {
					t.Fatalf("teardown hook: %v", err)
				}
				// Isolate the process-table check from other tests on the build box.
				probeAgent := "dcfx6agent" + strconv.Itoa(os.Getpid()) + name + strconv.FormatBool(running)
				original := agentProcessMayRun
				agentProcessMayRun = func(dir, got string) bool {
					if got != hookAgentProcessName(name) {
						t.Fatalf("checked agent %q, want %q", got, name)
					}
					return accountAgentProcessMayRun(dir, probeAgent)
				}
				t.Cleanup(func() { agentProcessMayRun = original })

				management := filepath.Join(t.TempDir(), "defenseclaw")
				if err := os.WriteFile(management, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
					t.Fatal(err)
				}
				prefix := ""
				if name == "devin" {
					prefix = "set -e; "
				}
				shell := exec.Command("bash", "-c", prefix+management+" setup remove "+probeAgent+"; printf 'done\\n'; sleep 30 & wait")
				shell.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
				out, err := shell.StdoutPipe()
				if err != nil {
					t.Fatal(err)
				}
				if err := shell.Start(); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = syscall.Kill(-shell.Process.Pid, syscall.SIGKILL); _ = shell.Wait() })
				if line, err := bufio.NewReader(out).ReadString('\n'); err != nil || line != "done\n" {
					t.Fatalf("management command did not complete: %q, %v", line, err)
				}
				if running {
					sleeper := testenv.NativeSleep(t)
					agentImage := filepath.Join(t.TempDir(), probeAgent)
					if err := os.Symlink(sleeper, agentImage); err != nil {
						t.Fatal(err)
					}
					agent := exec.Command(agentImage, "30")
					if err := agent.Start(); err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { _ = agent.Process.Kill(); _ = agent.Wait() })
				}
				if err := RemovePerUserConnectorHookFiles(opts, removed, nil); err != nil {
					t.Fatal(err)
				}
				_, err = os.Lstat(script)
				if running && err != nil || !running && !os.IsNotExist(err) {
					t.Fatalf("hook presence after removal with running=%t: %v", running, err)
				}
			})
		}
	}
}

func TestShellConnectorRemovalCommandKeepsUncertainWrappers(t *testing.T) {
	for _, tc := range []struct {
		command string
		removal bool
	}{
		{"defenseclaw setup remove devin; sleep 30 & wait", true},
		{"set -e; /usr/bin/defenseclaw setup remove devin --yes; printf done", true},
		{"echo \"old; defenseclaw setup remove devin\"; sleep 30", false},
		{"defenseclaw setup remove devin; devin", false},
		{"defenseclaw setup remove devin; source ./agent.sh", false},
		{"defenseclaw setup remove devin; $(cat ./script)", false},
	} {
		if got := isShellConnectorRemovalCommand(tc.command, "devin"); got != tc.removal {
			t.Errorf("management wrapper classification=%t, want %t for %q", got, tc.removal, tc.command)
		}
	}
}
