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

//go:build windows

package inventory

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// This smoke test inventories only the disposable go test process and does
// not terminate, suspend, or otherwise modify any process on the host.
func TestNativeWindowsProcessSnapshotSmoke(t *testing.T) {
	procs, err := platformProcessSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	classifyWindowsProcesses(procs, windowsAgentCatalog())
	counts := map[string]int{}
	for _, proc := range procs {
		if proc.Connector != "" {
			counts[proc.Connector]++
		}
	}
	t.Logf("native snapshot classified agent counts: %v", counts)
	pid := os.Getpid()
	for _, proc := range procs {
		if proc.PID == pid {
			if proc.Comm == "" || !proc.Windows {
				t.Fatalf("current process has incomplete base metadata: %+v", proc)
			}
			return
		}
	}
	t.Fatalf("current disposable test process PID %d missing from snapshot", pid)
}

// TestNativeWindowsNamedAgentProcessRefresh exercises the actual Toolhelp
// snapshot and usage refresh with disposable binaries whose basenames match
// the supported Windows agent aliases. The Claude helper's process DACL
// deliberately denies new metadata handles: Toolhelp must still retain and
// classify its base row instead of turning an authorization failure into a
// false "not running" result.
func TestNativeWindowsNamedAgentProcessRefresh(t *testing.T) {
	helpersDir := t.TempDir()
	codex := startNamedWindowsProcessHelper(t, helpersDir, "codex.exe")
	claude := startNamedWindowsProcessHelper(t, helpersDir, "claude.exe")
	restrictWindowsProcessMetadata(t, claude.cmd.Process.Pid)

	reader := nativeWindowsSnapshotReader{}
	if _, err := reader.Details(claude.cmd.Process.Pid); !errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		t.Fatalf("restricted Claude metadata error = %v, want ERROR_ACCESS_DENIED", err)
	}

	procs, err := platformProcessSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	classifyWindowsProcesses(procs, windowsAgentCatalog())
	byPID := make(map[int]processInfo, len(procs))
	for _, proc := range procs {
		byPID[proc.PID] = proc
	}
	codexProc, ok := byPID[codex.cmd.Process.Pid]
	if !ok || codexProc.Connector != "codex" || codexProc.User == "" || codexProc.StartedAt.IsZero() {
		t.Fatalf("named Codex snapshot row = %+v, present=%v", codexProc, ok)
	}
	claudeProc, ok := byPID[claude.cmd.Process.Pid]
	if !ok || claudeProc.Connector != "claudecode" {
		t.Fatalf("access-denied Claude snapshot row = %+v, present=%v", claudeProc, ok)
	}
	if claudeProc.User != "" || !claudeProc.StartedAt.IsZero() {
		t.Fatalf("restricted Claude row fabricated unavailable metadata: %+v", claudeProc)
	}

	dataDir := t.TempDir()
	svc := NewContinuousDiscoveryServiceWithOptions(AIDiscoveryOptions{
		Enabled:                 true,
		Mode:                    "enhanced",
		DataDir:                 dataDir,
		HomeDir:                 t.TempDir(),
		ScanRoots:               []string{t.TempDir()},
		MaxFilesPerScan:         8,
		IncludePackageManifests: false,
		IncludeShellHistory:     false,
		IncludeEnvVarNames:      false,
		IncludeNetworkDomains:   false,
	}, windowsAgentCatalog(), nil, nil)
	t.Cleanup(func() {
		if err := svc.Close(); err != nil {
			t.Errorf("close discovery service: %v", err)
		}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	// Drive the same process-only refresh path used by the service ticker. A
	// full API scan intentionally fans out across filesystem/package detectors
	// and would make this native process contract depend on unrelated host I/O.
	report, err := svc.runScan(ctx, false, "process")
	if err != nil {
		t.Fatalf("usage process refresh: %v", err)
	}
	runtimeByPID := map[int]*ProcessRuntime{}
	for i := range report.Signals {
		if report.Signals[i].Runtime != nil {
			runtimeByPID[report.Signals[i].Runtime.PID] = report.Signals[i].Runtime
		}
	}
	codexRuntime := runtimeByPID[codex.cmd.Process.Pid]
	if codexRuntime == nil || codexRuntime.StartedAt == nil || codexRuntime.User == "" || !strings.EqualFold(codexRuntime.Comm, "codex.exe") {
		t.Fatalf("Codex usage runtime = %+v", codexRuntime)
	}
	claudeRuntime := runtimeByPID[claude.cmd.Process.Pid]
	if claudeRuntime == nil || claudeRuntime.StartedAt != nil || claudeRuntime.User != "" || !strings.EqualFold(claudeRuntime.Comm, "claude.exe") {
		t.Fatalf("access-denied Claude usage runtime = %+v", claudeRuntime)
	}
}

// This test is also the subprocess entry point used by
// TestNativeWindowsNamedAgentProcessRefresh. The copied executable name is
// what Toolhelp reports; stdin gives the parent a bounded, handle-backed
// lifetime without shell commands or host process discovery.
func TestNativeWindowsNamedAgentProcessHelper(t *testing.T) {
	if os.Getenv("DEFENSECLAW_WINDOWS_PROCESS_HELPER") != "1" {
		return
	}
	_, _ = io.Copy(io.Discard, os.Stdin)
}

type namedWindowsProcessHelper struct {
	cmd   *exec.Cmd
	stdin io.WriteCloser
	done  chan error
}

func startNamedWindowsProcessHelper(t *testing.T, dir, name string) *namedWindowsProcessHelper {
	t.Helper()
	source, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(dir, name)
	copyWindowsTestExecutable(t, source, destination)
	cmd := exec.Command(destination, "-test.run=^TestNativeWindowsNamedAgentProcessHelper$")
	// The helper needs no host/provider environment. Keeping only its private
	// activation marker prevents credentials from being copied into a process
	// whose sole purpose is to appear in a local snapshot.
	cmd.Env = []string{"DEFENSECLAW_WINDOWS_PROCESS_HELPER=1"}
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		_ = stdin.Close()
		t.Fatalf("start %s helper: %v", name, err)
	}
	helper := &namedWindowsProcessHelper{cmd: cmd, stdin: stdin, done: make(chan error, 1)}
	go func() { helper.done <- cmd.Wait() }()
	t.Cleanup(func() { stopNamedWindowsProcessHelper(t, helper) })

	deadline := time.Now().Add(5 * time.Second)
	reader := nativeWindowsSnapshotReader{}
	for {
		if _, err := reader.Details(cmd.Process.Pid); err == nil {
			return helper
		}
		select {
		case waitErr := <-helper.done:
			t.Fatalf("%s helper exited before snapshot readiness: %v", name, waitErr)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s helper PID %d did not become queryable", name, cmd.Process.Pid)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func copyWindowsTestExecutable(t *testing.T, source, destination string) {
	t.Helper()
	in, err := os.Open(source)
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	out, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o700)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		t.Fatal(err)
	}
	if err := out.Close(); err != nil {
		t.Fatal(err)
	}
}

func stopNamedWindowsProcessHelper(t *testing.T, helper *namedWindowsProcessHelper) {
	t.Helper()
	_ = helper.stdin.Close()
	select {
	case err := <-helper.done:
		if err != nil {
			t.Errorf("named process helper exit: %v", err)
		}
	case <-time.After(5 * time.Second):
		_ = helper.cmd.Process.Kill()
		select {
		case <-helper.done:
		case <-time.After(5 * time.Second):
			t.Errorf("named process helper PID %d did not exit after kill", helper.cmd.Process.Pid)
		}
	}
}

func restrictWindowsProcessMetadata(t *testing.T, pid int) {
	t.Helper()
	handle, err := windows.OpenProcess(windows.READ_CONTROL|windows.WRITE_DAC, false, uint32(pid))
	if err != nil {
		t.Fatalf("open helper DACL: %v", err)
	}
	defer windows.CloseHandle(handle)
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		t.Fatal(err)
	}
	trustee := func(sid *windows.SID, trusteeType windows.TRUSTEE_TYPE) windows.TRUSTEE {
		return windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  trusteeType,
			TrusteeValue: windows.TrusteeValueFromSID(sid),
		}
	}
	acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{
		{
			AccessPermissions: windows.PROCESS_QUERY_LIMITED_INFORMATION,
			AccessMode:        windows.DENY_ACCESS,
			Trustee:           trustee(user.User.Sid, windows.TRUSTEE_IS_USER),
		},
		{
			AccessPermissions: windows.PROCESS_TERMINATE | windows.SYNCHRONIZE | windows.READ_CONTROL | windows.WRITE_DAC,
			AccessMode:        windows.GRANT_ACCESS,
			Trustee:           trustee(user.User.Sid, windows.TRUSTEE_IS_USER),
		},
		{
			AccessPermissions: windows.PROCESS_ALL_ACCESS,
			AccessMode:        windows.GRANT_ACCESS,
			Trustee:           trustee(system, windows.TRUSTEE_IS_WELL_KNOWN_GROUP),
		},
	}, nil)
	if err != nil {
		t.Fatalf("build helper process DACL: %v", err)
	}
	if err := windows.SetSecurityInfo(
		handle,
		windows.SE_KERNEL_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil,
		nil,
		acl,
		nil,
	); err != nil {
		t.Fatalf("restrict helper process DACL: %v", err)
	}
}
