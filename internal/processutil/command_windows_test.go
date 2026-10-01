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
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/windows"

	"github.com/defenseclaw/defenseclaw/internal/testenv"
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
	processTreeReleaseEnv     = "DEFENSECLAW_PROCESS_TREE_RELEASE"
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
		// Never released: only the captured job's termination (or the test
		// process exiting) ends this process.
		_, _ = testenv.AwaitRelease(os.Getenv(processTreeReleaseEnv))
		os.Exit(0)
	}
	if os.Getenv(processTreeHelperEnv) == "1" {
		grandchild := exec.Command(os.Args[0], "-test.run=^TestCombinedOutputTreeKillsGrandchildrenOnCancellation$")
		grandchild.Env = append(os.Environ(), processTreeGrandchildEnv+"=1")
		if err := grandchild.Start(); err != nil {
			os.Exit(21)
		}
		if err := testenv.PublishFile(
			os.Getenv(processTreePIDFileEnv),
			[]byte(strconv.Itoa(grandchild.Process.Pid)),
		); err != nil {
			os.Exit(22)
		}
		_, _ = testenv.AwaitRelease(os.Getenv(processTreeReleaseEnv))
		os.Exit(0)
	}

	pidFile := filepath.Join(t.TempDir(), "grandchild.pid")
	release := testenv.NewRelease(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cmd := CommandContext(ctx, os.Args[0], "-test.run=^TestCombinedOutputTreeKillsGrandchildrenOnCancellation$")
	cmd.Env = append(
		os.Environ(),
		processTreeHelperEnv+"=1",
		processTreePIDFileEnv+"="+pidFile,
		processTreeReleaseEnv+"="+release.Token(),
	)
	done := make(chan error, 1)
	go func() {
		_, err := CombinedOutputTree(cmd, false)
		done <- err
	}()

	// The helper publishes the grandchild PID only after starting it; if the
	// helper dies first, CombinedOutputTree returns and the wait fails at once.
	data, err := testenv.WaitForFile(pidFile, done)
	if err != nil {
		t.Fatalf("captured helper did not launch its grandchild: %v", err)
	}
	childPID, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		t.Fatal(err)
	}
	child := testenv.ProcessExit(t, childPID)

	cancel()
	if err := <-done; err == nil {
		t.Fatal("cancelled process tree returned success")
	}
	// The grandchild is never released, so its exit can only be the job
	// termination that cancellation performs.
	if code := <-child; code != 1 {
		t.Fatalf("grandchild exit code = %d, want 1 from captured-job termination", code)
	}
}

func TestCombinedOutputTreeCompletesWhenGrandchildInheritsOutput(t *testing.T) {
	if os.Getenv(inheritedOutputChildEnv) == "1" {
		_, _ = os.Stdout.WriteString("grandchild stdout\n")
		_, _ = os.Stderr.WriteString("grandchild stderr\n")
		if err := testenv.PublishFile(
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
		grandchildDone := make(chan error, 1)
		go func() { grandchildDone <- grandchild.Wait() }()
		data, err := testenv.WaitForFile(os.Getenv(processTreeMarkerEnv), grandchildDone)
		if err != nil {
			os.Exit(28)
		}
		if string(data) != "ready" {
			os.Exit(27)
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
		// Finish only after the test has observed this process outlive the
		// launcher's job; a child that did not break away is killed first.
		released, err := testenv.AwaitRelease(os.Getenv(processTreeReleaseEnv))
		if err != nil || !released {
			os.Exit(24)
		}
		if err := testenv.PublishFile(
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
		if err := testenv.PublishFile(
			os.Getenv(processTreePIDFileEnv),
			[]byte(strconv.Itoa(child.Process.Pid)),
		); err != nil {
			os.Exit(22)
		}
		return
	}

	dir := t.TempDir()
	marker := filepath.Join(dir, "managed-breakaway-finished")
	pidFile := filepath.Join(dir, "managed-breakaway.pid")
	release := testenv.NewRelease(t)
	cmd := CommandContext(context.Background(), os.Args[0], "-test.run=^TestCombinedOutputTreeAllowsExplicitManagedBreakaway$")
	cmd.Env = append(
		os.Environ(),
		managedBreakawayHelperEnv+"=1",
		processTreeMarkerEnv+"="+marker,
		processTreePIDFileEnv+"="+pidFile,
		processTreeReleaseEnv+"="+release.Token(),
	)
	if output, err := CombinedOutputTree(cmd, true); err != nil {
		t.Fatalf("managed launcher failed: %v: %s", err, output)
	}
	// The launcher exited and its job was terminated. The child blocks until
	// released, so it is still running only if it broke away from that job.
	data, err := os.ReadFile(pidFile)
	if err != nil {
		t.Fatalf("managed launcher did not publish its child: %v", err)
	}
	childPID, err := strconv.Atoi(string(data))
	if err != nil {
		t.Fatal(err)
	}
	exited := testenv.ProcessExit(t, childPID) // fails if the child is already gone
	release.Signal(t)
	if code := <-exited; code != 0 {
		t.Fatalf("explicitly managed breakaway process exit code = %d, want 0 after release", code)
	}
	if data, err := os.ReadFile(marker); err != nil || string(data) != "managed" {
		t.Fatalf("managed marker = %q, %v", data, err)
	}
}
