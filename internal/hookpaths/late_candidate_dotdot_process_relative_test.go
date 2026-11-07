// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

func TestLateCandidateDotDotThroughProcessRelativeLinkStaysUnproved(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux proc alias")
	}
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
	if err := os.WriteFile(filepath.Join(root, "hook", "status"), []byte("ordinary"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{filepath.Join(root, "agent", "status"), filepath.Join(project, "status")} {
		if err := os.Symlink(protected, path); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink("/proc/thread-self/cwd", filepath.Join(project, "jump")); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(project, "jump") + "/../status"
	t.Chdir(hookCWD)
	if data, err := os.ReadFile(target); err != nil || string(data) != "ordinary" {
		t.Fatalf("hook read=%q err=%v", data, err)
	}
	cmd := exec.Command("cat", target)
	cmd.Dir = agentCWD
	if data, err := cmd.Output(); err != nil || string(data) != "protected" {
		t.Fatalf("agent read=%q err=%v", data, err)
	}
	if got := ProtectedReach(target, home, NewTargetMemo()); got == GradeNone {
		t.Errorf("a process-relative link through a dot-dot returned None, but the agent can open the protected file")
	}
	if got := LateCallGrade("cat "+target, agentCWD, home); got == GradeNone {
		t.Errorf("late command with a process-relative link returned None, but the agent can open the protected file")
	}
}

func TestProcessRelativeLinkNamesOpenerRelativeForms(t *testing.T) {
	for path, want := range map[string]bool{
		"/proc/self/cwd":           true,
		"/proc/thread-self/root":   true,
		"/proc/self/task/5678/cwd": true,
		"/proc/self/fd/3":          true,
		"/dev/fd/3":                true,
		"/dev/stdout":              true,
		"/proc/1234/cwd":           false,
		"/proc/1234/task/5678/cwd": false,
		"/proc/1234/fd/3":          false,
		"/proc/self/status":        false,
		"/proc/self/task/x/cwd":    false,
		"/proc/cpuinfo":            false,
		"/home/user/project/jump":  false,
		"/tmp/proc/self/cwd":       false,
	} {
		if got := processRelativeLink(path); got != want {
			t.Errorf("processRelativeLink(%q)=%v want %v", path, got, want)
		}
	}
}

func TestFixedPIDLinkNamesTheLinkOfAnExplicitProcess(t *testing.T) {
	for path, want := range map[string]string{
		"/proc/1234/cwd":             "/proc/1234/cwd",
		"/proc/1234/cwd/sub/file":    "/proc/1234/cwd",
		"/proc/1234/root/etc":        "/proc/1234/root",
		"/proc/1234/exe":             "/proc/1234/exe",
		"/proc/1234/fd/3":            "/proc/1234/fd/3",
		"/proc/1234/fd/3/../status":  "/proc/1234/fd/3",
		"/proc/1234/task/5678/cwd/x": "/proc/1234/task/5678/cwd",
		"/proc/1234/map_files/a-b/x": "/proc/1234/map_files/a-b",
		"/proc/1234/fd":              "",
		"/proc/1234/fd/":             "",
		"/proc/1234/status":          "",
		"/proc/1234/task/x/cwd":      "",
		"/proc/12a4/cwd":             "",
		"/proc/self/cwd":             "",
		"/tmp/proc/1234/cwd":         "",
		"/home/user/project/jump":    "",
	} {
		got, ok := fixedPIDLink(path)
		if got != want || ok != (want != "") {
			t.Errorf("fixedPIDLink(%q)=%q,%v want %q", path, got, ok, want)
		}
	}
}

func TestLateCandidateDotDotRelativeAndNestedLinks(t *testing.T) {
	for _, protectedPhysical := range []bool{false, true} {
		label := "ordinary_physical"
		if protectedPhysical {
			label = "protected_physical"
		}
		t.Run(label, func(t *testing.T) {
			root := t.TempDir()
			home := filepath.Join(root, "home")
			project := filepath.Join(root, "project")
			other := filepath.Join(root, "other")
			protected := filepath.Join(home, ".defenseclaw", "cache", "entry")
			for _, dir := range []string{filepath.Dir(protected), project, filepath.Join(project, "plain"), filepath.Join(other, "child")} {
				if err := os.MkdirAll(dir, 0700); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(protected, []byte("protected"), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("../other/child", filepath.Join(project, "jump")); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("jump", filepath.Join(project, "chain")); err != nil {
				t.Fatal(err)
			}
			ordinary := func(path string) {
				t.Helper()
				if err := os.WriteFile(path, []byte("ordinary"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			link := func(path string) {
				t.Helper()
				if err := os.Symlink(protected, path); err != nil {
					t.Fatal(err)
				}
			}
			if protectedPhysical {
				ordinary(filepath.Join(project, "status"))
				link(filepath.Join(other, "status"))
			} else {
				link(filepath.Join(project, "status"))
				ordinary(filepath.Join(other, "status"))
			}
			linked := filepath.Join(project, "jump")
			t.Chdir(linked)
			data, err := os.ReadFile("../status")
			if err != nil {
				t.Fatal(err)
			}
			wantBytes := "ordinary"
			want := GradeNone
			twin := GradeNamed
			if protectedPhysical {
				wantBytes, want, twin = "protected", GradeNamed, GradeNone
			}
			if string(data) != wantBytes {
				t.Fatalf("kernel read=%q want=%q", data, wantBytes)
			}
			for _, row := range []struct{ command, dir string }{
				{"cat ../status", linked},
				{"cat ./../status", linked},
				{"cat " + linked + "/../status", linked},
				{"cat jump/../status", project},
				{"cat chain/../status", project},
				{"cat jump/../child/../status", project},
				{"cat -- jump/../status", project},
				{"grep -f jump/../status x", project},
				{"grep --file=jump/../status x", project},
			} {
				if got := LateCallGrade(row.command, row.dir, home); got != want {
					t.Errorf("%q from %q grade=%s want=%s", row.command, row.dir, got, want)
				}
			}
			if got := LateCallGrade("cat status", project, home); got != twin {
				t.Errorf("direct twin grade=%s want=%s", got, twin)
			}
			if got := ProtectedReach(project+"/chain/../status", home, NewTargetMemo()); got != want {
				t.Errorf("nested link reach=%s want=%s", got, want)
			}
			if got := ProtectedSSHReach(project+"/chain/../status", home, NewTargetMemo()); got != GradeNone {
				t.Errorf("non-SSH target marked SSH: %s", got)
			}
		})
	}
}

func TestLateCandidateDotDotFinalProtectedLinkStaysNamed(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "home")
	ssh := filepath.Join(home, ".ssh")
	ordinary := filepath.Join(root, "ordinary")
	if err := os.MkdirAll(filepath.Join(ssh, "plain"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ordinary, []byte("ordinary"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(ordinary, filepath.Join(ssh, "authorized_keys")); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{
		filepath.Join(ssh, "authorized_keys"),
		ssh + "/plain/../authorized_keys",
		ssh + "/plain/../../.ssh/authorized_keys",
	} {
		if got := ProtectedReach(path, home, NewTargetMemo()); got != GradeNamed {
			t.Errorf("protected link %q grade=%s want Named", path, got)
		}
		if got := ProtectedSSHReach(path, home, NewTargetMemo()); got != GradeNamed {
			t.Errorf("SSH protected link %q grade=%s want Named", path, got)
		}
	}
}
