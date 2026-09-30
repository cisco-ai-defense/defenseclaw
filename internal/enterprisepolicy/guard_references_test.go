// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// digestOf evaluates req and returns the single finding's digest.
func digestOf(t *testing.T, req GuardRequest) Finding {
	t.Helper()
	decision := EvaluateForeignHooks(req)
	if len(decision.Findings) != 1 {
		t.Fatalf("want one finding: %+v", decision)
	}
	return decision.Findings[0]
}

// An approval binds the script a command runs even when the command names
// it without a path (bash check.sh, node x.js, python3 x.py, pwsh -File
// x.ps1): the same handler text in another repository must not admit a
// different file of that name.
func TestGuardApprovalCoversScriptsNamedWithoutAPath(t *testing.T) {
	for _, command := range []string{"bash check.sh", "node check.js", "python3 check.py", "pwsh -NoProfile -File check.ps1"} {
		req := guardRequest(t, "cursor", config.ForeignHooksRemove)
		repo := filepath.Dir(req.WorkingDir)
		script := strings.Fields(command)[len(strings.Fields(command))-1]
		writeFile(t, filepath.Join(repo, ".cursor", "hooks.json"), `{"version": 1, "hooks": {"preToolUse": [{"command": `+jsonString(command)+`}]}}`)
		writeFile(t, filepath.Join(repo, script), "reviewed")
		first := digestOf(t, req)
		if first.Allowed || strings.HasPrefix(first.Reason, unapprovableReason) {
			t.Fatalf("%s: a reviewable finding: %+v", command, first)
		}
		req.Policy.AllowedHooks = []string{first.Digest}
		if decision := EvaluateForeignHooks(req); decision.Deny {
			t.Fatalf("%s: the reviewed hook is approved: %+v", command, decision)
		}
		writeFile(t, filepath.Join(repo, script), "different")
		if decision := EvaluateForeignHooks(req); !decision.Deny {
			t.Fatalf("%s: another %s behind an approved handler must deny", command, script)
		}
	}
}

// Relative words also resolve against the agent's working directory, a
// handler's cwd field (Copilot) and a directory the command changes into,
// and environment values (BASH_ENV) are references too.
func TestGuardDigestFollowsWorkingDirectoriesAndEnvironment(t *testing.T) {
	cases := map[string]struct {
		connector, file, handler string
		script                   func(repo, workingDir string) string
	}{
		"working directory": {"cursor", ".cursor/hooks.json", `{"command": "bash check.sh"}`,
			func(_, workingDir string) string { return filepath.Join(workingDir, "check.sh") }},
		"cd in the command": {"cursor", ".cursor/hooks.json", `{"command": "cd hooks && ./run.sh"}`,
			func(repo, _ string) string { return filepath.Join(repo, "hooks", "run.sh") }},
		"copilot cwd field": {"copilot", ".github/hooks/x.json", `{"type": "command", "bash": "./check.sh", "cwd": "scripts"}`,
			func(repo, _ string) string { return filepath.Join(repo, "scripts", "check.sh") }},
		"environment value": {"copilot", ".github/hooks/x.json", `{"type": "command", "bash": "true", "env": {"BASH_ENV": "env.sh"}}`,
			func(repo, _ string) string { return filepath.Join(repo, "env.sh") }},
	}
	for name, tc := range cases {
		req := guardRequest(t, tc.connector, config.ForeignHooksRemove)
		repo := filepath.Dir(req.WorkingDir)
		if err := os.MkdirAll(req.WorkingDir, 0o755); err != nil {
			t.Fatal(err)
		}
		writeFile(t, filepath.Join(repo, filepath.FromSlash(tc.file)), `{"version": 1, "hooks": {"preToolUse": [`+tc.handler+`]}}`)
		script := tc.script(repo, req.WorkingDir)
		writeFile(t, script, "one")
		before := digestOf(t, req)
		if strings.HasPrefix(before.Reason, unapprovableReason) {
			t.Fatalf("%s: a reviewable finding: %+v", name, before)
		}
		writeFile(t, script, "two")
		if after := digestOf(t, req); after.Digest == before.Digest {
			t.Fatalf("%s: %s must be part of the digest", name, script)
		}
	}

	// A file that is not there does not enter the digest, so the approval
	// does not depend on the directory the agent was started in.
	req := guardRequest(t, "cursor", config.ForeignHooksRemove)
	repo := filepath.Dir(req.WorkingDir)
	writeFile(t, filepath.Join(repo, ".cursor", "hooks.json"), `{"version": 1, "hooks": {"preToolUse": [{"command": "bash check.sh"}]}}`)
	writeFile(t, filepath.Join(repo, "check.sh"), "reviewed")
	atRoot := req
	atRoot.WorkingDir = repo
	if digestOf(t, req).Digest != digestOf(t, atRoot).Digest {
		t.Fatal("starting the agent in a subdirectory without a check.sh must not change the digest")
	}
}

// A reference the digest cannot bind makes the finding unapprovable: an
// allowlisted digest must not admit whatever an unresolved variable, an
// oversized file or a command past the word bound runs.
func TestGuardUnboundReferencesAreNeverApproved(t *testing.T) {
	words := make([]string, 0, guardReferencedTokenLimit+2)
	for i := 0; i <= guardReferencedTokenLimit; i++ {
		words = append(words, fmt.Sprintf("w%d", i))
	}
	cases := map[string]struct {
		command string
		setup   func(t *testing.T, repo string)
		want    string
	}{
		"unresolved variable": {command: "bash $HOOKS_DIR/check.sh", want: "variable DefenseClaw cannot resolve"},
		"tilde form":          {command: "bash ~+/check.sh", want: "variable DefenseClaw cannot resolve"},
		"large file": {command: "bash ./big.sh", want: "is larger than", setup: func(t *testing.T, repo string) {
			path := filepath.Join(repo, "big.sh")
			writeFile(t, path, "")
			if err := os.Truncate(path, guardReferencedFileLimit+1); err != nil {
				t.Fatal(err)
			}
		}},
		"too many words": {command: "echo " + strings.Join(words, " "), want: "more than"},
	}
	for name, tc := range cases {
		req := guardRequest(t, "cursor", config.ForeignHooksRemove)
		repo := filepath.Dir(req.WorkingDir)
		if tc.setup != nil {
			tc.setup(t, repo)
		}
		writeFile(t, filepath.Join(repo, ".cursor", "hooks.json"), `{"version": 1, "hooks": {"preToolUse": [{"command": `+jsonString(tc.command)+`}]}}`)
		first := EvaluateForeignHooks(req)
		if !first.Deny || len(first.Findings) != 1 || !strings.HasPrefix(first.Findings[0].Reason, unapprovableReason) ||
			!strings.Contains(first.Reason, tc.want) || !strings.Contains(first.Reason, "cannot be approved") {
			t.Fatalf("%s: must deny as unapprovable: %+v", name, first)
		}
		req.Policy.AllowedHooks = []string{first.Findings[0].Digest}
		if decision := EvaluateForeignHooks(req); !decision.Deny {
			t.Fatalf("%s: an unapprovable finding must not be approved by its digest: %+v", name, decision)
		}
	}
}

// Ordinary inline commands stay approvable: a shell variable that carries
// data, a literal percent sign, an option and a jq filter are not file
// references.
func TestGuardInlineCommandsStayApprovable(t *testing.T) {
	for _, command := range []string{
		`f=$(jq -r .tool_input.file_path); [ -n "$f" ] && npx prettier --write "$f"`,
		`printf '%s\n' done`,
		`cd "$CLAUDE_PROJECT_DIR" && bash check.sh`,
	} {
		req := guardRequest(t, "cursor", config.ForeignHooksRemove)
		repo := filepath.Dir(req.WorkingDir)
		writeFile(t, filepath.Join(repo, ".cursor", "hooks.json"), `{"version": 1, "hooks": {"preToolUse": [{"command": `+jsonString(command)+`}]}}`)
		first := digestOf(t, req)
		if strings.HasPrefix(first.Reason, unapprovableReason) {
			t.Fatalf("%q must be approvable: %+v", command, first)
		}
		req.Policy.AllowedHooks = []string{first.Digest}
		if decision := EvaluateForeignHooks(req); decision.Deny {
			t.Fatalf("%q: the reviewed hook is approved: %+v", command, decision)
		}
	}
}

// The cleanup still removes a user-level entry it cannot approve: the
// entry is readable, only its references are unbound.
func TestCleanupRemovesUnapprovableUserHooks(t *testing.T) {
	req := guardRequest(t, "cursor", config.ForeignHooksRemove)
	userHooks := filepath.Join(req.Home, ".cursor", "hooks.json")
	writeFile(t, userHooks, `{"version": 1, "hooks": {"preToolUse": [`+ownedCursorEntry+`, {"command": "bash $HOOKS_DIR/x.sh"}]}}`)
	result, err := CleanUserForeignHooks(req, time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Removed) != 1 || strings.Contains(readFile(t, userHooks), "HOOKS_DIR") {
		t.Fatalf("the unapprovable user hook must be removed: %+v", result)
	}
}

// Past the scan's reference budget the cleanup reports instead of
// removing: an approved entry may look unapprovable only because the scan
// stopped binding it.
func TestCleanupDoesNotRemoveEntriesPastTheScanBudget(t *testing.T) {
	req := guardRequest(t, "cursor", config.ForeignHooksRemove)
	words := make([]string, 0, guardReferencedTokenLimit)
	for i := 1; i < guardReferencedTokenLimit; i++ {
		words = append(words, fmt.Sprintf("w%d", i))
	}
	handler := `{"command": ` + jsonString("echo "+strings.Join(words, " ")) + `}`
	handlers := make([]string, 0, 64)
	for i := 0; i*guardReferencedTokenLimit <= 2*guardScanReferenceLimit; i++ {
		handlers = append(handlers, handler)
	}
	userHooks := filepath.Join(req.Home, ".cursor", "hooks.json")
	body := `{"version": 1, "hooks": {"preToolUse": [` + strings.Join(handlers, ", ") + `]}}`
	writeFile(t, userHooks, body)
	result, err := CleanUserForeignHooks(req, time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Removed) != 0 || len(result.Reported) == 0 || readFile(t, userHooks) != body {
		t.Fatalf("a scan past its budget must report, not rewrite: removed=%d reported=%d", len(result.Removed), len(result.Reported))
	}
}
