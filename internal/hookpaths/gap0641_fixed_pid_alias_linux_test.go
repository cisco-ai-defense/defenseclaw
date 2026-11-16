// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

// An opener-relative alias that a link leads to reads as the hook own process
// id. The numeric id it resolves to must not be taken for an explicit one.
func TestGAP0641AliasThroughLinkStaysUnprovedWithoutDotDot(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux proc alias")
	}
	for _, alias := range []string{"/proc/self/cwd", "/proc/thread-self/cwd"} {
		t.Run(filepath.Base(filepath.Dir(alias)), func(t *testing.T) {
			root := t.TempDir()
			home := filepath.Join(root, "home")
			protected := filepath.Join(home, ".defenseclaw", "cache", "entry")
			project := filepath.Join(root, "project")
			hookCWD := filepath.Join(root, "hook", "child")
			agentCWD := filepath.Join(root, "agent", "child")
			for _, dir := range []string{filepath.Dir(protected), project, hookCWD, agentCWD} {
				if err := os.MkdirAll(dir, 0700); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(protected, []byte("protected"), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(hookCWD, "status"), []byte("ordinary"), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(protected, filepath.Join(agentCWD, "status")); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(alias, filepath.Join(project, "jump")); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("jump", filepath.Join(project, "chain")); err != nil {
				t.Fatal(err)
			}
			t.Chdir(hookCWD)
			for _, target := range []string{
				filepath.Join(project, "jump", "status"),
				filepath.Join(project, "chain", "status"),
			} {
				cmd := exec.Command("cat", target)
				cmd.Dir = agentCWD
				if data, err := cmd.Output(); err != nil || string(data) != "protected" {
					t.Fatalf("agent read %q = %q, %v", target, data, err)
				}
				if got := ProtectedReach(target, home, NewTargetMemo()); got == GradeNone {
					t.Errorf("%q returned None, but the agent can open the protected file", target)
				}
				if got := LateCallGrade("cat "+target, agentCWD, home); got == GradeNone {
					t.Errorf("late command on %q returned None, but the agent can open the protected file", target)
				}
			}
		})
	}
}

// A process id that is gone, or a descriptor that is not a file path, is not
// proved: the path stays uncertain rather than ordinary.
func TestGAP0641FixedPIDLinkUnprovedWhenNotReadable(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux proc path")
	}
	home := filepath.Join(t.TempDir(), "home")
	if err := os.MkdirAll(filepath.Join(home, ".defenseclaw"), 0700); err != nil {
		t.Fatal(err)
	}
	gone := exec.Command("true")
	if err := gone.Run(); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{
		fmt.Sprintf("/proc/%d/cwd/status", gone.Process.Pid),
		fmt.Sprintf("/proc/%d/cwd/../status", gone.Process.Pid),
	} {
		if got := ProtectedReach(path, home, NewTargetMemo()); got == GradeNone {
			t.Errorf("%q of a process that is gone returned None", path)
		}
	}
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	defer writer.Close()
	link := fmt.Sprintf("/proc/%d/fd/%d", os.Getpid(), reader.Fd())
	if fixedPIDLinkProved(link) {
		t.Errorf("%q leads to a pipe, not a path, and was proved", link)
	}
	if got := ProtectedReach(link+"/x", home, NewTargetMemo()); got == GradeNone {
		t.Errorf("%q returned None", link+"/x")
	}
}
