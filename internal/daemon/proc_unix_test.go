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

//go:build !windows

package daemon

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestProveStaleDaemonProcessRequiresExactLinuxIdentity(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux /proc identity proof")
	}

	dataDir := t.TempDir()
	d := New(dataDir)
	sleep, err := exec.LookPath("sleep")
	if err != nil {
		t.Skipf("sleep unavailable: %v", err)
	}
	resolvedSleep, err := filepath.EvalSymlinks(sleep)
	if err != nil {
		t.Fatalf("resolve sleep: %v", err)
	}

	start := func(environment []string) *exec.Cmd {
		t.Helper()
		command := exec.Command(resolvedSleep, "30")
		command.Env = environment
		if err := command.Start(); err != nil {
			t.Fatalf("start helper: %v", err)
		}
		t.Cleanup(func() {
			_ = command.Process.Kill()
			_, _ = command.Process.Wait()
		})
		return command
	}

	withoutIdentityKey := func(environment []string, key string) []string {
		cleaned := make([]string, 0, len(environment))
		for _, entry := range environment {
			name, _, _ := strings.Cut(entry, "=")
			if name != key {
				cleaned = append(cleaned, entry)
			}
		}
		return cleaned
	}
	waitForVisibleEnvironment := func(command *exec.Cmd) {
		t.Helper()
		path := fmt.Sprintf("/proc/%d/environ", command.Process.Pid)
		deadline := time.Now().Add(250 * time.Millisecond)
		for attempts := 1; ; attempts++ {
			environment, err := os.ReadFile(path)
			if err == nil && len(environment) > 0 {
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf(
					"helper environment was not visible after %d attempts: environ_bytes=%d environ_err=%v",
					attempts,
					len(environment),
					err,
				)
			}
			time.Sleep(time.Millisecond)
		}
	}

	matching := start(d.childEnv(os.Environ()))
	deadline := time.Now().Add(250 * time.Millisecond)
	for attempts := 1; ; attempts++ {
		identity, ok := d.proveStaleDaemonProcess(matching.Process.Pid, resolvedSleep)
		if ok && identity != "" {
			break
		}
		if time.Now().After(deadline) {
			actualExecutable, executableErr := os.Readlink(fmt.Sprintf("/proc/%d/exe", matching.Process.Pid))
			environment, environmentErr := os.ReadFile(fmt.Sprintf("/proc/%d/environ", matching.Process.Pid))
			t.Fatalf(
				"exact executable, daemon marker, and data directory were not proven after %d attempts: executable=%q executable_err=%v environ_bytes=%d environ_err=%v",
				attempts,
				actualExecutable,
				executableErr,
				len(environment),
				environmentErr,
			)
		}
		time.Sleep(time.Millisecond)
	}
	if _, ok := d.proveStaleDaemonProcess(matching.Process.Pid, "/nonexistent/gateway"); ok {
		t.Fatal("mismatched executable was accepted")
	}
	if _, ok := New(filepath.Join(dataDir, "other")).proveStaleDaemonProcess(
		matching.Process.Pid,
		resolvedSleep,
	); ok {
		t.Fatal("mismatched data directory was accepted")
	}

	withoutMarker := start(withoutIdentityKey(d.childEnv(os.Environ()), EnvDaemon))
	waitForVisibleEnvironment(withoutMarker)
	if _, ok := d.proveStaleDaemonProcess(withoutMarker.Process.Pid, resolvedSleep); ok {
		t.Fatal("process without daemon marker was accepted")
	}

	withoutDataDir := start(withoutIdentityKey(d.childEnv(os.Environ()), EnvDataDir))
	waitForVisibleEnvironment(withoutDataDir)
	if _, ok := d.proveStaleDaemonProcess(withoutDataDir.Process.Pid, resolvedSleep); ok {
		t.Fatal("process without data-directory marker was accepted")
	}
}

func TestProveStaleDaemonProcessRejectsCurrentMutatorWrapper(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux /proc identity proof")
	}
	d := New(t.TempDir())
	if _, ok := d.proveStaleDaemonProcess(os.Getpid(), "/usr/bin/defenseclaw-gateway"); ok {
		t.Fatal("non-gateway controller process was accepted from an argv-style match")
	}
}

func TestProtectedDaemonPIDsDistinguishesMissingFromMalformedIdentity(t *testing.T) {
	dataDir := t.TempDir()
	d := New(dataDir)

	tracked, watchdog, err := d.protectedDaemonPIDs()
	if err != nil || tracked != 0 || watchdog != 0 {
		t.Fatalf("missing identity files = (%d, %d, %v), want (0, 0, nil)", tracked, watchdog, err)
	}

	if err := os.WriteFile(d.pidFile, []byte("not-a-pid"), 0o600); err != nil {
		t.Fatalf("write malformed gateway pid: %v", err)
	}
	if _, _, err := d.protectedDaemonPIDs(); !errors.Is(err, ErrUnsafeProcessIdentity) {
		t.Fatalf("malformed gateway identity error = %v, want ErrUnsafeProcessIdentity", err)
	}

	if err := os.WriteFile(d.pidFile, []byte("1234\n"), 0o600); err != nil {
		t.Fatalf("write gateway pid: %v", err)
	}
	watchdogPath := filepath.Join(dataDir, "watchdog.pid")
	if err := os.WriteFile(watchdogPath, []byte("not-a-pid"), 0o600); err != nil {
		t.Fatalf("write malformed watchdog pid: %v", err)
	}
	if _, _, err := d.protectedDaemonPIDs(); !errors.Is(err, ErrUnsafeProcessIdentity) {
		t.Fatalf("malformed watchdog identity error = %v, want ErrUnsafeProcessIdentity", err)
	}

	if err := os.WriteFile(watchdogPath, []byte("{\"pid\":5678,\"executable\":\"/test/watchdog\"}\n"), 0o600); err != nil {
		t.Fatalf("write watchdog pid: %v", err)
	}
	tracked, watchdog, err = d.protectedDaemonPIDs()
	if err != nil || tracked != 1234 || watchdog != 5678 {
		t.Fatalf("valid identity files = (%d, %d, %v), want (1234, 5678, nil)", tracked, watchdog, err)
	}
}
