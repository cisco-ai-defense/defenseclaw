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

//go:build windows

package processutil

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

const (
	processTreeHelperEnv      = "DEFENSECLAW_PROCESS_TREE_HELPER"
	processTreeGrandchildEnv  = "DEFENSECLAW_PROCESS_TREE_GRANDCHILD"
	processTreePIDFileEnv     = "DEFENSECLAW_PROCESS_TREE_PID_FILE"
	processTreeMarkerEnv      = "DEFENSECLAW_PROCESS_TREE_MARKER"
	managedBreakawayHelperEnv = "DEFENSECLAW_MANAGED_BREAKAWAY_HELPER"
	managedBreakawayChildEnv  = "DEFENSECLAW_MANAGED_BREAKAWAY_CHILD"
	inheritedOutputHelperEnv  = "DEFENSECLAW_PROCESSUTIL_INHERITED_OUTPUT_HELPER"
	inheritedOutputChildEnv   = "DEFENSECLAW_PROCESSUTIL_INHERITED_OUTPUT_CHILD"
)

func TestCommandContextPreventsConsoleAllocation(t *testing.T) {
	cmd := CommandContext(context.Background(), "cmd.exe", "/d", "/c", "exit", "0")
	if cmd.SysProcAttr == nil {
		t.Fatal("captured command missing Windows process attributes")
	}
	if cmd.SysProcAttr.CreationFlags&windows.CREATE_NO_WINDOW == 0 {
		t.Fatalf("captured command creation flags = %#x, missing CREATE_NO_WINDOW", cmd.SysProcAttr.CreationFlags)
	}
	if !cmd.SysProcAttr.HideWindow {
		t.Fatal("captured command must hide any inherited startup window")
	}
	if err := cmd.Run(); err != nil {
		t.Fatalf("hidden captured command failed: %v", err)
	}
}

func TestCombinedOutputTreeKillsGrandchildrenOnCancellation(t *testing.T) {
	if os.Getenv(processTreeGrandchildEnv) == "1" {
		time.Sleep(30 * time.Second)
		return
	}
	if os.Getenv(processTreeHelperEnv) == "1" {
		grandchild := exec.Command(os.Args[0], "-test.run=^TestCombinedOutputTreeKillsGrandchildrenOnCancellation$")
		grandchild.Env = append(os.Environ(), processTreeGrandchildEnv+"=1")
		if err := grandchild.Start(); err != nil {
			os.Exit(21)
		}
		if err := publishProcessTreeFixture(
			os.Getenv(processTreePIDFileEnv),
			[]byte(strconv.Itoa(grandchild.Process.Pid)),
		); err != nil {
			os.Exit(22)
		}
		time.Sleep(30 * time.Second)
		return
	}

	pidFile := filepath.Join(t.TempDir(), "grandchild.pid")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cmd := CommandContext(ctx, os.Args[0], "-test.run=^TestCombinedOutputTreeKillsGrandchildrenOnCancellation$")
	cmd.Env = append(
		os.Environ(),
		processTreeHelperEnv+"=1",
		processTreePIDFileEnv+"="+pidFile,
	)
	done := make(chan error, 1)
	go func() {
		_, err := CombinedOutputTree(cmd, false)
		done <- err
	}()

	var childPID int
	deadline := time.Now().Add(5 * time.Second)
	for childPID == 0 {
		data, err := os.ReadFile(pidFile)
		if err == nil {
			childPID, err = strconv.Atoi(strings.TrimSpace(string(data)))
			if err != nil {
				t.Fatal(err)
			}
		} else if !processTreeFixtureNotReady(err) {
			t.Fatal(err)
		}
		if childPID == 0 {
			if time.Now().After(deadline) {
				t.Fatal("captured helper did not launch its grandchild")
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	child, err := windows.OpenProcess(windows.SYNCHRONIZE, false, uint32(childPID))
	if err != nil {
		t.Fatalf("open grandchild %d: %v", childPID, err)
	}
	defer windows.CloseHandle(child)

	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancelled process tree returned success")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("cancelled process tree did not return promptly")
	}
	result, err := windows.WaitForSingleObject(child, 5000)
	if err != nil {
		t.Fatalf("wait for cancelled grandchild: %v", err)
	}
	if result != windows.WAIT_OBJECT_0 {
		t.Fatalf("grandchild wait result = %#x, want terminated", result)
	}
}

func TestCombinedOutputTreeCompletesWhenGrandchildInheritsOutput(t *testing.T) {
	if os.Getenv(inheritedOutputChildEnv) == "1" {
		_, _ = os.Stdout.WriteString("grandchild stdout\n")
		_, _ = os.Stderr.WriteString("grandchild stderr\n")
		if err := publishProcessTreeFixture(
			os.Getenv(processTreeMarkerEnv),
			[]byte("ready"),
		); err != nil {
			os.Exit(26)
		}
		time.Sleep(30 * time.Second)
		return
	}
	if os.Getenv(inheritedOutputHelperEnv) == "1" {
		grandchild := exec.Command(os.Args[0], "-test.run=^TestCombinedOutputTreeCompletesWhenGrandchildInheritsOutput$")
		grandchild.Env = append(os.Environ(), inheritedOutputChildEnv+"=1")
		grandchild.Stdout = os.Stdout
		grandchild.Stderr = os.Stderr
		if err := grandchild.Start(); err != nil {
			os.Exit(25)
		}
		deadline := time.Now().Add(5 * time.Second)
		for {
			data, err := os.ReadFile(os.Getenv(processTreeMarkerEnv))
			if err == nil {
				if string(data) != "ready" {
					os.Exit(27)
				}
				break
			}
			if !processTreeFixtureNotReady(err) || time.Now().After(deadline) {
				os.Exit(28)
			}
			time.Sleep(10 * time.Millisecond)
		}
		_, _ = os.Stdout.WriteString("helper complete\n")
		return
	}

	marker := filepath.Join(t.TempDir(), "inherited-output-ready")
	cmd := CommandContext(context.Background(), os.Args[0], "-test.run=^TestCombinedOutputTreeCompletesWhenGrandchildInheritsOutput$")
	cmd.Env = append(
		os.Environ(),
		inheritedOutputHelperEnv+"=1",
		processTreeMarkerEnv+"="+marker,
	)
	cmd.WaitDelay = 250 * time.Millisecond
	output, err := CombinedOutputTree(cmd, false)
	if err != nil {
		t.Fatalf("successful helper with inherited output handles failed: %v: %s", err, output)
	}
	for _, expected := range []string{"grandchild stdout", "grandchild stderr", "helper complete"} {
		if !strings.Contains(string(output), expected) {
			t.Fatalf("captured output %q is missing %q", output, expected)
		}
	}
}

func TestCapturedJobFlagsLimitBreakawayToManagedLaunches(t *testing.T) {
	ordinary := capturedJobLimitFlags(false)
	if ordinary&windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE == 0 {
		t.Fatal("ordinary captured job is missing KILL_ON_JOB_CLOSE")
	}
	if ordinary&windows.JOB_OBJECT_LIMIT_BREAKAWAY_OK != 0 {
		t.Fatal("ordinary captured job unexpectedly allows breakaway")
	}
	managed := capturedJobLimitFlags(true)
	if managed&windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE == 0 ||
		managed&windows.JOB_OBJECT_LIMIT_BREAKAWAY_OK == 0 {
		t.Fatalf("managed captured job flags = %#x", managed)
	}
}

func TestCombinedOutputTreeAllowsExplicitManagedBreakaway(t *testing.T) {
	if os.Getenv(managedBreakawayChildEnv) == "1" {
		time.Sleep(300 * time.Millisecond)
		if err := publishProcessTreeFixture(
			os.Getenv(processTreeMarkerEnv),
			[]byte("managed"),
		); err != nil {
			os.Exit(24)
		}
		return
	}
	if os.Getenv(managedBreakawayHelperEnv) == "1" {
		child := exec.Command(os.Args[0], "-test.run=^TestCombinedOutputTreeAllowsExplicitManagedBreakaway$")
		child.Env = append(os.Environ(), managedBreakawayChildEnv+"=1")
		child.SysProcAttr = &syscall.SysProcAttr{
			CreationFlags: windows.CREATE_BREAKAWAY_FROM_JOB | windows.DETACHED_PROCESS | windows.CREATE_NEW_PROCESS_GROUP,
			HideWindow:    true,
		}
		if err := child.Start(); err != nil {
			os.Exit(23)
		}
		return
	}

	marker := filepath.Join(t.TempDir(), "managed-breakaway-finished")
	cmd := CommandContext(context.Background(), os.Args[0], "-test.run=^TestCombinedOutputTreeAllowsExplicitManagedBreakaway$")
	cmd.Env = append(os.Environ(), managedBreakawayHelperEnv+"=1", processTreeMarkerEnv+"="+marker)
	if output, err := CombinedOutputTree(cmd, true); err != nil {
		t.Fatalf("managed launcher failed: %v: %s", err, output)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		data, err := os.ReadFile(marker)
		if err == nil {
			if string(data) != "managed" {
				t.Fatalf("managed marker = %q", data)
			}
			break
		}
		if !processTreeFixtureNotReady(err) {
			t.Fatal(err)
		}
		if time.Now().After(deadline) {
			t.Fatal("explicitly managed breakaway process did not survive launcher exit")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func publishProcessTreeFixture(path string, data []byte) error {
	temporary, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if _, err := temporary.Write(data); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporaryPath, path)
}

func processTreeFixtureNotReady(err error) bool {
	return errors.Is(err, os.ErrNotExist) ||
		errors.Is(err, windows.ERROR_SHARING_VIOLATION) ||
		errors.Is(err, windows.ERROR_LOCK_VIOLATION)
}
