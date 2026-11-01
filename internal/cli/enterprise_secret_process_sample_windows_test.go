//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	seamRecoveryHelperEnv  = "DC_SEAM_RECOVERY_HELPER"
	seamRecoveryCaptureEnv = "DC_SEAM_RECOVERY_CAPTURE"
	// processCommandLineInformation is PROCESSINFOCLASS 60.
	processCommandLineInformation = 60
)

// TestWindowsSecretRecoveryChildHelperProcess stands in for the
// `enterprise secret recover-gateway` child in the A-W07 seam test: it says
// READY, keeps every byte of its control pipe and exits at EOF.
func TestWindowsSecretRecoveryChildHelperProcess(t *testing.T) {
	if os.Getenv(seamRecoveryHelperEnv) != "1" {
		return
	}
	_, _ = os.Stdout.WriteString("READY\n")
	control, _ := io.ReadAll(os.Stdin)
	_ = os.WriteFile(os.Getenv(seamRecoveryCaptureEnv), control, 0o600)
	os.Exit(0)
}

// A-W07 (mgmt-agent-api:GAP-1308): while `enterprise secret set
// --from-stdin` writes a credential, no process on the computer carries the
// value: not this command, not the gateway recovery child it starts before
// the write (its command line, its environment, its control pipe). The
// gateway restart decision is the seam: the credential is on disk then and
// the child runs, so the process list is sampled at that instant, with no
// timing involved.
func TestWindowsSecretSetKeepsTheValueOutOfEveryProcessAtTheWriteInstant(t *testing.T) {
	dir := windowsSecretTestHarness(t)
	value := seamSecretValue(t)
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	capture := filepath.Join(t.TempDir(), "recovery-control.bin")

	savedSpawn, savedStart := windowsSecretSpawnRecovery, windowsSecretStartRecovery
	t.Cleanup(func() { windowsSecretSpawnRecovery, windowsSecretStartRecovery = savedSpawn, savedStart })
	// The real spawn path: os.Executable, windowsSecretRecoveryCommand, the
	// pipes and the readiness wait. Only the image is swapped for the helper,
	// which keeps the product's arguments on its real command line.
	windowsSecretSpawnRecovery = spawnWindowsSecretGatewayRecovery
	var productArgs, productEnv []string
	var child *os.Process
	windowsSecretStartRecovery = func(cmd *exec.Cmd) error {
		productArgs = append([]string(nil), cmd.Args...)
		productEnv = cmd.Env
		if productEnv == nil {
			productEnv = os.Environ()
		}
		cmd.Path = executable
		cmd.Args = append([]string{executable, "-test.run=^TestWindowsSecretRecoveryChildHelperProcess$", "--"}, productArgs[1:]...)
		cmd.Env = append(append([]string(nil), productEnv...), seamRecoveryHelperEnv+"=1", seamRecoveryCaptureEnv+"="+capture)
		if err := cmd.Start(); err != nil {
			return err
		}
		// A second handle: the product releases its own, the test waits on this.
		p, err := os.FindProcess(cmd.Process.Pid)
		if err != nil {
			return err
		}
		child = p
		return nil
	}

	credential := filepath.Join(dir, "ai-defense-api-key")
	sampled := false
	windowsSecretRestartGateway = func(beforeStop func() error) (bool, error) {
		if err := beforeStop(); err != nil {
			return false, err
		}
		stored, err := os.ReadFile(credential)
		if err != nil || string(stored) != value {
			t.Errorf("the credential is not written at the restart decision (%d bytes, %v)", len(stored), err)
		}
		if child == nil {
			t.Fatal("no gateway recovery child runs at the write instant")
		}
		lines := seamSampleCommandLines(t)
		line, ok := lines[uint32(child.Pid)]
		if !ok || !strings.Contains(line, "recover-gateway") {
			t.Errorf("the process sample missed the recovery child %d (%q)", child.Pid, line)
		}
		for pid, line := range lines {
			if strings.Contains(line, value) {
				t.Errorf("process %d carries the credential value on its command line at the write instant", pid)
			}
		}
		sampled = true
		return true, nil
	}

	out, err := runWindowsSecretCommand(t, "set", enterpriseSecretOptions{name: "ai-defense-api-key", fromStdin: true, json: true}, value+"\n")
	if err != nil {
		t.Fatalf("set: %v", err)
	}
	if !sampled {
		t.Fatal("the gateway restart decision never ran, so nothing was sampled")
	}
	if strings.Contains(out, value) {
		t.Error("the set result carries the credential value")
	}
	if strings.Contains(strings.Join(os.Args, " "), value) {
		t.Error("this command's own arguments carry the credential value")
	}
	if strings.Contains(strings.Join(productArgs, " "), value) {
		t.Error("the recovery child's arguments carry the credential value")
	}
	for _, kv := range productEnv {
		if strings.Contains(kv, value) {
			t.Errorf("the recovery child's environment carries the credential value (%s)", strings.SplitN(kv, "=", 2)[0])
		}
	}
	if _, err := child.Wait(); err != nil {
		t.Fatalf("wait for the recovery child: %v", err)
	}
	control, err := os.ReadFile(capture)
	if err != nil {
		t.Fatalf("the recovery child kept no control capture: %v", err)
	}
	if strings.Contains(string(control), value) {
		t.Error("the recovery child's control pipe carried the credential value")
	}
	if !strings.HasPrefix(string(control), "ARM\n") {
		t.Errorf("control pipe = %q, want the ARM the restart decision writes", control)
	}
}

func seamSecretValue(t *testing.T) string {
	t.Helper()
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	return "seam-aw07-" + hex.EncodeToString(raw)
}

// seamSampleCommandLines reads the command line of every process this
// account may query (PROCESS_QUERY_LIMITED_INFORMATION).
func seamSampleCommandLines(t *testing.T) map[uint32]string {
	t.Helper()
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(snapshot)
	lines := map[uint32]string{}
	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))
	for err = windows.Process32First(snapshot, &entry); err == nil; err = windows.Process32Next(snapshot, &entry) {
		if line, ok := seamCommandLine(entry.ProcessID); ok {
			lines[entry.ProcessID] = line
		}
	}
	if len(lines) == 0 {
		t.Fatal(fmt.Errorf("no process command line could be sampled"))
	}
	return lines
}

func seamCommandLine(pid uint32) (string, bool) {
	process, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return "", false
	}
	defer windows.CloseHandle(process)
	buf := make([]byte, 1<<16)
	var size uint32
	if err := windows.NtQueryInformationProcess(process, processCommandLineInformation, unsafe.Pointer(&buf[0]), uint32(len(buf)), &size); err != nil {
		return "", false
	}
	return (*windows.NTUnicodeString)(unsafe.Pointer(&buf[0])).String(), true
}
