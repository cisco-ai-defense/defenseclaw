// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package processutil

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// GAP-0418: a killed gateway left its skill-scanner running; RunTree asks the
// kernel to kill the child with its parent.
func TestRunTreeChildExitsWithItsParent(t *testing.T) {
	cmd := CommandContext(context.Background(), "true")
	if err := RunTree(cmd); err != nil {
		t.Fatal(err)
	}
	if cmd.SysProcAttr == nil || cmd.SysProcAttr.Pdeathsig != syscall.SIGKILL || !cmd.SysProcAttr.Setpgid {
		t.Fatalf("SysProcAttr = %+v, want Pdeathsig SIGKILL in a process group of its own", cmd.SysProcAttr)
	}
}

// p0 GAP-1156: a process the scanner started (its LLM helper) ends with the
// scanner, when the scanner exits and when its command is canceled.
func TestRunTreeKillsWhatTheChildStarted(t *testing.T) {
	for _, tc := range []struct {
		name    string
		script  string
		timeout time.Duration
	}{
		{"child exits", `sleep 60 & echo $! > "$1"; exit 0`, time.Minute},
		{"command canceled", `sleep 60 & echo $! > "$1"; wait`, time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pidFile := filepath.Join(t.TempDir(), "helper.pid")
			ctx, cancel := context.WithTimeout(context.Background(), tc.timeout)
			defer cancel()
			_ = RunTree(CommandContext(ctx, "/bin/sh", "-c", tc.script, "sh", pidFile))
			raw, err := os.ReadFile(pidFile)
			if err != nil {
				t.Fatal(err)
			}
			pid, err := strconv.Atoi(strings.TrimSpace(string(raw)))
			if err != nil {
				t.Fatal(err)
			}
			deadline := time.Now().Add(5 * time.Second)
			for helperRunning(pid) {
				if time.Now().After(deadline) {
					_ = syscall.Kill(pid, syscall.SIGKILL)
					t.Fatalf("helper %d still runs after its parent ended", pid)
				}
				time.Sleep(20 * time.Millisecond)
			}
		})
	}
}

// A helper the scanner started ends when the gateway is killed with
// SIGKILL: no cleanup of the gateway runs then, and the parent-death signal
// ends the scanner only.
func TestRunTreeKillsWhatTheChildStartedWhenTheParentIsKilled(t *testing.T) {
	if os.Getenv("PROCESSUTIL_TEST_GATEWAY") != "" {
		return
	}
	marker := strconv.Itoa(7000+os.Getpid()%1000) + "." + strconv.FormatInt(time.Now().UnixNano()%1000000, 10)
	gateway := exec.Command(os.Args[0], "-test.run=^TestRunTreeHelperGateway$")
	gateway.Env = append(os.Environ(), "PROCESSUTIL_TEST_GATEWAY="+marker)
	if err := gateway.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = gateway.Process.Kill(); _ = gateway.Wait() })
	deadline := time.Now().Add(10 * time.Second)
	helper := 0
	for helper == 0 {
		if time.Now().After(deadline) {
			t.Fatal("the scanner's helper did not start")
		}
		time.Sleep(20 * time.Millisecond)
		helper = sleepWithArg(marker)
	}
	if err := gateway.Process.Signal(syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	_ = gateway.Wait()
	deadline = time.Now().Add(5 * time.Second)
	for helperRunning(helper) {
		if time.Now().After(deadline) {
			_ = syscall.Kill(helper, syscall.SIGKILL)
			t.Fatalf("helper %d still runs after the gateway was killed", helper)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestRunTreeHelperGateway is the gateway of the test above: it runs a
// scanner that starts a helper and waits for it.
func TestRunTreeHelperGateway(t *testing.T) {
	marker := os.Getenv("PROCESSUTIL_TEST_GATEWAY")
	if marker == "" {
		t.Skip("runs as the gateway of TestRunTreeKillsWhatTheChildStartedWhenTheParentIsKilled")
	}
	_ = RunTree(CommandContext(context.Background(), "/bin/sh", "-c", `sleep "$1" & wait`, "sh", marker))
}

// The MCP launcher creates its own session and leaves a server child in it.
// Killing the gateway must still end both generations of that process tree.
func TestRunTreeIsolatedKillsDetachedMCPServerAfterGatewaySIGKILL(t *testing.T) {
	if os.Getenv("PROCESSUTIL_TEST_ISOLATED_GATEWAY") != "" {
		return
	}
	if _, err := exec.LookPath("setsid"); err != nil {
		t.Skip("setsid is unavailable")
	}
	marker := strconv.Itoa(7000+os.Getpid()%1000) + "." + strconv.FormatInt(time.Now().UnixNano()%1000000, 10)
	gateway := exec.Command(os.Args[0], "-test.run=^TestRunTreeIsolatedHelperGateway$")
	gateway.Env = append(os.Environ(), "PROCESSUTIL_TEST_ISOLATED_GATEWAY="+marker)
	if err := gateway.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = gateway.Process.Kill(); _ = gateway.Wait() })
	deadline := time.Now().Add(10 * time.Second)
	server := 0
	for server == 0 {
		if time.Now().After(deadline) {
			t.Fatal("detached MCP server did not start")
		}
		time.Sleep(20 * time.Millisecond)
		server = sleepWithArg(marker)
	}
	contained := processesWithArg(marker)
	if len(contained) < 3 {
		t.Fatalf("scanner fixture has %d processes, want scanner, detached launcher and child", len(contained))
	}
	if err := gateway.Process.Signal(syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	_ = gateway.Wait()
	deadline = time.Now().Add(5 * time.Second)
	for anyProcessRunning(contained) {
		if time.Now().After(deadline) {
			for _, pid := range contained {
				_ = syscall.Kill(pid, syscall.SIGKILL)
			}
			t.Fatalf("MCP launcher, server or child survived gateway SIGKILL: %v", contained)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func anyProcessRunning(pids []int) bool {
	for _, pid := range pids {
		if helperRunning(pid) {
			return true
		}
	}
	return false
}

func processesWithArg(arg string) []int {
	entries, _ := os.ReadDir("/proc")
	var pids []int
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		raw, err := os.ReadFile(filepath.Join("/proc", entry.Name(), "cmdline"))
		if err == nil && strings.Contains(string(raw), "\x00"+arg+"\x00") {
			pids = append(pids, pid)
		}
	}
	return pids
}

func TestRunTreeIsolatedHelperGateway(t *testing.T) {
	marker := os.Getenv("PROCESSUTIL_TEST_ISOLATED_GATEWAY")
	if marker == "" {
		t.Skip("helper process")
	}
	cmd := CommandContext(context.Background(), "/bin/sh", "-c", `setsid /bin/sh -c 'sleep "$1" & wait' sh "$1" & wait`, "sh", marker)
	_ = RunTreeIsolated(context.Background(), cmd)
}

func TestRunTreeIsolatedKeepsNormalScannerExitStatus(t *testing.T) {
	for i := 0; i < 20; i++ {
		if err := RunTreeIsolated(context.Background(), CommandContext(context.Background(), "/bin/true")); err != nil {
			t.Fatalf("normal scanner exit %d: %v", i, err)
		}
	}
}

// sleepWithArg is the pid of a running "sleep arg", or 0.
func sleepWithArg(arg string) int {
	entries, _ := os.ReadDir("/proc")
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		raw, err := os.ReadFile(filepath.Join("/proc", entry.Name(), "cmdline"))
		if err == nil && strings.HasSuffix(string(raw), "\x00"+arg+"\x00") && strings.Contains(string(raw), "sleep\x00") {
			return pid
		}
	}
	return 0
}

// helperRunning reports a live, not zombie, process.
func helperRunning(pid int) bool {
	raw, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "stat"))
	if err != nil {
		return false
	}
	fields := strings.Fields(string(raw[strings.LastIndexByte(string(raw), ')')+1:]))
	return len(fields) > 0 && fields[0] != "Z"
}
