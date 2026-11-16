// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package openshell

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestManagedE2fsprogsPackageFallback(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("macOS tool selection")
	}
	root, err := os.MkdirTemp(os.TempDir(), "e2fs-package-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	// Package tools must be traversable by every sandbox account.
	if err := os.Chmod(root, 0o755); err != nil {
		t.Fatal(err)
	}
	packageDir := filepath.Join(root, "package")
	packageTools := filepath.Join(packageDir, "sbin")
	home := filepath.Join(root, "home")
	writeTools := func(dir string) {
		t.Helper()
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		for _, name := range AdminE2fsprogsTools {
			if err := os.WriteFile(filepath.Join(dir, name), []byte("tool"), 0o755); err != nil {
				t.Fatal(err)
			}
		}
	}
	writeTools(packageTools)
	trust := func(string, bool) error { return nil }
	choose := func(admin string, check func(string, bool) error) (string, string) {
		return managedE2fsprogsToolDir(admin, packageDir, home, os.Getuid(), check)
	}
	if dir, problem := choose("", trust); dir != packageTools || problem != "" {
		t.Fatalf("package fallback = %q, %q", dir, problem)
	}
	badTrust := func(string, bool) error { return errors.New("untrusted") }
	if dir, problem := choose("", badTrust); dir != "" || !strings.Contains(problem, "not trusted") {
		t.Fatalf("untrusted package = %q, %q", dir, problem)
	}
	admin := filepath.Join(root, "admin")
	writeTools(filepath.Join(admin, "sbin"))
	if dir, problem := choose(admin, trust); dir != filepath.Join(admin, "sbin") || problem != "" {
		t.Fatalf("explicit administrator directory = %q, %q", dir, problem)
	}
	if dir, problem := choose(filepath.Join(root, "missing"), trust); dir != "" || !strings.Contains(problem, "missing") {
		t.Fatalf("broken explicit directory fell back: %q, %q", dir, problem)
	}
	writeTools(filepath.Join(home, ".local", "opt", "e2fsprogs", "sbin"))
	if dir, problem := choose("", trust); dir != filepath.Join(home, ".local", "opt", "e2fsprogs", "sbin") || problem != "" {
		t.Fatalf("account build priority = %q, %q", dir, problem)
	}
}

// rel-1-0-3 GAP-0197: an unprivileged process cannot stat tools below a
// private directory. An unused inaccessible sbin must not hide a usable
// bin; once bin also becomes inaccessible, the refusal names it and repair.
func TestManagedE2fsprogsInaccessibleCandidatesNameTheRepair(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("requires an unprivileged POSIX process")
	}
	root, err := os.MkdirTemp("", "e2fs-inaccessible-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	if err := os.Chmod(root, 0o755); err != nil {
		t.Fatal(err)
	}
	sbin, bin := filepath.Join(root, "sbin"), filepath.Join(root, "bin")
	for _, dir := range []string{sbin, bin} {
		if err := os.Mkdir(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })
	}
	for _, tool := range AdminE2fsprogsTools {
		if err := os.WriteFile(filepath.Join(bin, tool), []byte("tool"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(sbin, 0); err != nil {
		t.Fatal(err)
	}
	trust := func(string, bool) error { return nil }
	if dir, problem := ManagedE2fsprogsToolDir(root, "", os.Getuid(), trust); dir != bin || problem != "" {
		t.Fatalf("unused private sbin hid bin: %q, %q", dir, problem)
	}
	if err := os.Chmod(bin, 0); err != nil {
		t.Fatal(err)
	}
	for _, configured := range []string{root, bin} {
		dir, problem := ManagedE2fsprogsToolDir(configured, "", os.Getuid(), trust)
		if dir != "" || !strings.Contains(problem, bin) || !strings.Contains(problem, "chmod o+x") {
			t.Fatalf("inaccessible %s: %q, %q", configured, dir, problem)
		}
	}
	if dir, problem := managedE2fsprogsToolDir("", root, "", os.Getuid(), trust); dir != "" ||
		!strings.Contains(problem, bin) || !strings.Contains(problem, "chmod o+x") {
		t.Fatalf("inaccessible package tools: %q, %q", dir, problem)
	}
}

// The administrator's e2fsprogs_dir may be the install prefix (tools in its
// sbin or bin) or the folder that holds the tools; the folder returned holds
// both, and nothing else is accepted (GAP-0506).
func TestAdminE2fsprogsToolDir(t *testing.T) {
	files := func(paths ...string) func(string) bool {
		set := map[string]bool{}
		for _, p := range paths {
			set[filepath.FromSlash(p)] = true
		}
		return func(p string) bool { return set[p] }
	}
	prefix := "/opt/cisco/defenseclaw-deps/e2fsprogs"
	cases := []struct {
		name, dir string
		isFile    func(string) bool
		want      string
	}{
		{"prefix with sbin", prefix, files(prefix+"/sbin/mke2fs", prefix+"/sbin/debugfs"), prefix + "/sbin"},
		{"prefix with bin", prefix, files(prefix+"/bin/mke2fs", prefix+"/bin/debugfs"), prefix + "/bin"},
		// The rc.1 wave's configuration: the sbin folder itself.
		{"the tool folder", prefix + "/sbin", files(prefix+"/sbin/mke2fs", prefix+"/sbin/debugfs"), prefix + "/sbin"},
		{"tools split over sbin and bin", prefix, files(prefix+"/sbin/mke2fs", prefix+"/bin/debugfs"), ""},
		{"debugfs missing", prefix, files(prefix + "/sbin/mke2fs"), ""},
		{"empty", "", files(), ""},
	}
	for _, c := range cases {
		if got := AdminE2fsprogsToolDir(filepath.FromSlash(c.dir), c.isFile); got != filepath.FromSlash(c.want) {
			t.Errorf("%s: AdminE2fsprogsToolDir(%q) = %q, want %q", c.name, c.dir, got, c.want)
		}
	}
}

func TestManagedE2fsprogsToolDirUsesTheGatewayOrder(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("managed MicroVM e2fsprogs resolution is macOS and Linux only; os.Getuid is -1 on Windows")
	}
	root := t.TempDir()
	home := filepath.Join(root, "home")
	own := filepath.Join(home, ".local", "opt", "e2fsprogs", "sbin")
	if err := os.MkdirAll(own, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, tool := range AdminE2fsprogsTools {
		if err := os.WriteFile(filepath.Join(own, tool), []byte("tool"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	trust := func(string, bool) error { return nil }
	uid := os.Getuid()
	if dir, problem := ManagedE2fsprogsToolDir("", home, uid, trust); dir != own || problem != "" {
		t.Fatalf("account build = %q, %q", dir, problem)
	}
	if err := os.Remove(filepath.Join(own, "debugfs")); err != nil {
		t.Fatal(err)
	}
	if dir, problem := ManagedE2fsprogsToolDir("", home, uid, trust); dir != "" ||
		!strings.Contains(problem, "enterprise.openshell.e2fsprogs_dir") ||
		!strings.Contains(problem, "~/.local/opt/e2fsprogs/sbin") ||
		!strings.Contains(problem, "Homebrew keg is not used") {
		t.Fatalf("no account build = %q, %q", dir, problem)
	}
	if err := os.WriteFile(filepath.Join(own, "debugfs"), []byte("tool"), 0o755); err != nil {
		t.Fatal(err)
	}
	admin := filepath.Join(root, "bad-admin")
	if dir, problem := ManagedE2fsprogsToolDir(admin, home, uid, trust); dir != "" || !strings.Contains(problem, admin) {
		t.Fatalf("broken configured directory fell back to the account build: %q, %q", dir, problem)
	}
}
