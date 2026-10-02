// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterprisepolicy

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// evaluateWithin fails the test instead of hanging when the guard blocks.
func evaluateWithin(t *testing.T, req GuardRequest) GuardDecision {
	t.Helper()
	done := make(chan GuardDecision, 1)
	go func() { done <- EvaluateForeignHooks(req) }()
	select {
	case decision := <-done:
		return decision
	case <-time.After(10 * time.Second):
		t.Fatal("the guard blocked on a hook path")
		return GuardDecision{}
	}
}

// A FIFO or unreadable file named by a handler's command cannot be bound,
// so the handler cannot be approved, and naming it must not block the
// guard.
func TestGuardUnboundSpecialOrUnreadableReferences(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads any file")
	}
	for name, setup := range map[string]func(path string) error{
		"fifo": func(path string) error { return syscall.Mkfifo(path, 0o600) },
		"unreadable": func(path string) error {
			if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
				return err
			}
			return os.Chmod(path, 0)
		},
	} {
		req := guardRequest(t, "cursor", config.ForeignHooksRemove)
		repo := filepath.Dir(req.WorkingDir)
		if err := setup(filepath.Join(repo, "check.sh")); err != nil {
			t.Fatal(err)
		}
		writeFile(t, filepath.Join(repo, ".cursor", "hooks.json"), `{"version": 1, "hooks": {"preToolUse": [{"command": "bash check.sh"}]}}`)
		first := evaluateWithin(t, req)
		if !first.Deny || len(first.Findings) != 1 || !strings.HasPrefix(first.Findings[0].Reason, unapprovableReason) {
			t.Fatalf("%s: must deny as unapprovable: %+v", name, first)
		}
		req.Policy.AllowedHooks = []string{first.Findings[0].Digest}
		if decision := evaluateWithin(t, req); !decision.Deny {
			t.Fatalf("%s: an unapprovable finding must stay denied: %+v", name, decision)
		}
	}
}

// Node-based agents read a named pipe with fs.readFile and load whatever a
// writer sends. A FIFO (or any non-regular file) at a hook path cannot be
// verified, so it must deny instead of counting as absent, and the guard
// must not block opening it.
func TestGuardFailsClosedOnNonRegularHookPaths(t *testing.T) {
	for name, tc := range map[string]struct {
		connector string
		rel       func(req GuardRequest) string
	}{
		"project file":        {"cursor", func(req GuardRequest) string { return filepath.Join(req.WorkingDir, "..", ".cursor", "hooks.json") }},
		"user flat-dir entry": {"copilot", func(req GuardRequest) string { return filepath.Join(req.Home, ".copilot", "hooks", "a.json") }},
		"flat-dir itself":     {"copilot", func(req GuardRequest) string { return filepath.Join(req.WorkingDir, "..", ".github", "hooks") }},
		"plugin entry": {"opencode", func(req GuardRequest) string {
			return filepath.Join(req.Home, ".config", "opencode", "plugins", "x.js")
		}},
		"plugin dir itself": {"amp", func(req GuardRequest) string { return filepath.Join(req.WorkingDir, "..", ".amp", "plugins") }},
	} {
		req := guardRequest(t, tc.connector, config.ForeignHooksRemove)
		path := tc.rel(req)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := syscall.Mkfifo(path, 0o600); err != nil {
			t.Fatal(err)
		}
		decision := evaluateWithin(t, req)
		if !decision.Deny || !strings.Contains(decision.Reason, "cannot be verified") {
			t.Fatalf("%s: a FIFO at %s must fail closed: %+v", name, path, decision)
		}
	}

	req := guardRequest(t, "cursor", config.ForeignHooksRemove)
	userHooks := filepath.Join(req.Home, ".cursor", "hooks.json")
	if err := os.MkdirAll(filepath.Dir(userHooks), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(userHooks, 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := CleanUserForeignHooks(req, time.Now())
	if err != nil || len(result.Removed) != 0 || len(result.Reported) != 1 {
		t.Fatalf("cleanup must report, not remove or skip, a FIFO: %+v %v", result, err)
	}
}

// A home reached through a symlink (macOS temporary directories, some
// network homes) is still the home when the resolved working directory is
// walked: the walk stops there and each file is scanned once.
func TestGuardRecognizesAHomeBehindASymlink(t *testing.T) {
	real := filepath.Join(t.TempDir(), "real-home")
	if err := os.MkdirAll(filepath.Join(real, "scratch"), 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "home")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	req := guardRequest(t, "cursor", config.ForeignHooksRemove)
	req.Home = link
	req.WorkingDir = filepath.Join(link, "scratch")
	writeFile(t, filepath.Join(real, ".cursor", "hooks.json"), `{"version": 1, "hooks": {"preToolUse": [{"command": "./rewrite.sh"}]}}`)
	decision := EvaluateForeignHooks(req)
	if !decision.Deny || len(decision.Findings) != 1 || decision.Findings[0].Scope != ScopeUser {
		t.Fatalf("the home's hook file must be found once, as a user source: %+v", decision)
	}
}

// adminOwnedPrograms returns up to n distinct administrator-owned programs
// named name found in dirs.
func adminOwnedPrograms(dirs []string, names []string, n int) []string {
	var out []string
	seen := map[string]bool{}
	for _, name := range names {
		for _, dir := range dirs {
			path := filepath.Join(dir, name)
			info, err := os.Stat(path)
			resolved, resolveErr := filepath.EvalSymlinks(path)
			if err != nil || resolveErr != nil || !info.Mode().IsRegular() || !adminOwnedFile(info) || seen[resolved] {
				continue
			}
			seen[resolved] = true
			out = append(out, path)
			if len(out) == n {
				return out
			}
		}
	}
	return out
}

// An administrator-owned program is bound by kind only, but a link of the
// user's own that reaches one (the named file itself, or a folder above
// it) can be pointed at another, so the approval binds the link targets:
// retargeting the link changes the digest. Links the OS owns (a merged
// /bin) do not change how a program is bound.
func TestGuardDigestBindsUserLinksToAdministratorOwnedPrograms(t *testing.T) {
	programs := adminOwnedPrograms([]string{"/usr/bin", "/bin"}, []string{"true", "false", "env", "sh", "test"}, 2)
	if len(programs) < 2 {
		t.Skip("needs two administrator-owned programs")
	}
	req := guardRequest(t, "cursor", config.ForeignHooksRemove)
	repo := filepath.Dir(req.WorkingDir)
	writeFile(t, filepath.Join(repo, ".cursor", "hooks.json"), `{"version": 1, "hooks": {"preToolUse": [{"command": "./tool --check"}]}}`)
	link := filepath.Join(repo, "tool")
	retarget := func(target string) {
		t.Helper()
		_ = os.Remove(link)
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
	}
	retarget(programs[0])
	first := digestOf(t, req)
	if strings.HasPrefix(first.Reason, unapprovableReason) {
		t.Fatalf("a link to an administrator-owned program stays approvable: %+v", first)
	}
	req.Policy.AllowedHooks = []string{first.Digest}
	if decision := EvaluateForeignHooks(req); decision.Deny {
		t.Fatalf("the reviewed hook is approved: %+v", decision)
	}
	retarget(programs[1])
	if decision := EvaluateForeignHooks(req); !decision.Deny {
		t.Fatalf("pointing the approved link at %s must deny: %+v", programs[1], decision)
	}

	// A folder link above the program is bound the same way.
	for _, name := range []string{"true", "false", "env", "sh", "test"} {
		if len(adminOwnedPrograms([]string{"/usr/bin"}, []string{name}, 1)) == 0 || len(adminOwnedPrograms([]string{"/bin"}, []string{name}, 1)) == 0 {
			continue
		}
		writeFile(t, filepath.Join(repo, ".cursor", "hooks.json"), `{"version": 1, "hooks": {"preToolUse": [{"command": "./bin/`+name+`"}]}}`)
		folder := filepath.Join(repo, "bin")
		if err := os.Symlink("/usr/bin", folder); err != nil {
			t.Fatal(err)
		}
		req.Policy.AllowedHooks = nil
		req.Policy.AllowedHooks = []string{digestOf(t, req).Digest}
		if decision := EvaluateForeignHooks(req); decision.Deny {
			t.Fatalf("the reviewed hook is approved: %+v", decision)
		}
		_ = os.Remove(folder)
		if err := os.Symlink("/bin", folder); err != nil {
			t.Fatal(err)
		}
		if decision := EvaluateForeignHooks(req); !decision.Deny {
			t.Fatalf("pointing the approved folder link at /bin must deny: %+v", decision)
		}
		break
	}

	// No user link: the program is bound by kind, whatever links the OS
	// keeps above it.
	scan := newGuardScan(req)
	for _, program := range programs {
		if state := scan.fileState(program); state != "system" {
			t.Fatalf("%s: an administrator-owned program reached without a user link is bound by kind only: %q", program, state)
		}
	}
}
