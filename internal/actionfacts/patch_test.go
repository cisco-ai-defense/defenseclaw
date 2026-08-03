// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestAnalyzeApplyPatchEnvelopeProjectsExactChanges(t *testing.T) {
	patch := strings.Join([]string{
		"*** Begin Patch",
		"*** Add File: src/new.go",
		"+package sample",
		"+*** Delete File: hunk-bait.go",
		"*** Update File: src/edit.go",
		"@@",
		"-old",
		"+new",
		" *** Delete File: context-bait.go",
		"*** Update File: src/old.go",
		"*** Move to: src/moved.go",
		"@@",
		"-before move",
		"+after move",
		"*** End of File",
		"*** Delete File: src/gone.go",
		"*** End Patch",
		"",
	}, "\n")

	for _, test := range []struct {
		tool, field string
	}{
		{tool: "apply_patch", field: "command"},
		{tool: "applypatch", field: "patch"},
		{tool: "apply-patch", field: "patchText"},
		{tool: "apply_patch", field: "patch_text"},
	} {
		t.Run(test.tool+"/"+test.field, func(t *testing.T) {
			args, err := json.Marshal(map[string]any{
				test.field: patch,
				"cwd":      "/workspace",
			})
			if err != nil {
				t.Fatal(err)
			}
			facts := Analyze(Input{Tool: test.tool, Args: args})
			if !facts.Authoritative() || !facts.EnforcementEligible() ||
				facts.Parse.Dialect != DialectArgv || len(facts.Commands) != 1 {
				t.Fatalf("parse/commands = %#v/%#v", facts.Parse, facts.Commands)
			}
			for _, operation := range []OperationKind{
				OperationExecute, OperationWrite, OperationDelete, OperationMove,
			} {
				if !factsHaveOperation(facts, operation) {
					t.Fatalf("missing operation %q in %#v", operation, facts.Commands)
				}
			}
			for _, want := range []struct {
				path, resolved string
				access         PathAccess
			}{
				{path: "src/new.go", resolved: "/workspace/src/new.go", access: PathAccessWrite},
				{path: "src/edit.go", resolved: "/workspace/src/edit.go", access: PathAccessWrite},
				{path: "src/old.go", resolved: "/workspace/src/old.go", access: PathAccessDelete},
				{path: "src/moved.go", resolved: "/workspace/src/moved.go", access: PathAccessWrite},
				{path: "src/gone.go", resolved: "/workspace/src/gone.go", access: PathAccessDelete},
			} {
				if !patchFactsHavePath(facts, want.path, want.resolved, want.access) {
					t.Fatalf("missing path %#v in %#v", want, facts.Paths)
				}
			}
			if len(facts.Paths) != 5 {
				t.Fatalf("hunk bait produced paths: %#v", facts.Paths)
			}
		})
	}
}

func TestAnalyzeApplyPatchRejectsUncertainEnvelopes(t *testing.T) {
	valid := "*** Begin Patch\n*** Add File: safe.go\n+safe\n*** End Patch"
	many := strings.Builder{}
	many.WriteString("*** Begin Patch\n")
	for index := 0; index <= maxPatchDirectives; index++ {
		fmt.Fprintf(&many, "*** Add File: file-%03d.go\n+x\n", index)
	}
	many.WriteString("*** End Patch")

	tests := []struct {
		name   string
		fields map[string]any
		status ParseStatus
	}{
		{name: "missing begin", fields: map[string]any{"patch": "*** Add File: a.go\n+x\n*** End Patch"}, status: StatusInvalid},
		{name: "outside content", fields: map[string]any{"patch": valid + "\ntrailing"}, status: StatusInvalid},
		{name: "unknown directive", fields: map[string]any{"patch": "*** Begin Patch\n*** Rename File: a.go\n*** End Patch"}, status: StatusInvalid},
		{name: "content before file", fields: map[string]any{"patch": "*** Begin Patch\n+orphan\n*** Add File: a.go\n+x\n*** End Patch"}, status: StatusInvalid},
		{name: "invalid add line", fields: map[string]any{"patch": "*** Begin Patch\n*** Add File: a.go\n-old\n*** End Patch"}, status: StatusInvalid},
		{name: "empty update", fields: map[string]any{"patch": "*** Begin Patch\n*** Update File: a.go\n*** End Patch"}, status: StatusInvalid},
		{name: "pure move", fields: map[string]any{"patch": "*** Begin Patch\n*** Update File: a.go\n*** Move to: b.go\n*** End Patch"}, status: StatusInvalid},
		{name: "header-only update hunk", fields: map[string]any{"patch": "*** Begin Patch\n*** Update File: a.go\n@@\n*** End Patch"}, status: StatusInvalid},
		{name: "update before hunk", fields: map[string]any{"patch": "*** Begin Patch\n*** Update File: a.go\n-old\n+new\n*** End Patch"}, status: StatusInvalid},
		{name: "content after delete", fields: map[string]any{"patch": "*** Begin Patch\n*** Delete File: a.go\n-old\n*** End Patch"}, status: StatusInvalid},
		{name: "late move", fields: map[string]any{"patch": "*** Begin Patch\n*** Update File: a.go\n@@\n-old\n+new\n*** Move to: b.go\n*** End Patch"}, status: StatusInvalid},
		{name: "move without update", fields: map[string]any{"patch": "*** Begin Patch\n*** Move to: b.go\n*** End Patch"}, status: StatusInvalid},
		{name: "eof outside update", fields: map[string]any{"patch": "*** Begin Patch\n*** End of File\n*** Delete File: a.go\n*** End Patch"}, status: StatusInvalid},
		{name: "content after eof", fields: map[string]any{"patch": "*** Begin Patch\n*** Update File: a.go\n@@\n-old\n+new\n*** End of File\n+late\n*** End Patch"}, status: StatusInvalid},
		{name: "duplicate path", fields: map[string]any{"patch": "*** Begin Patch\n*** Add File: a.go\n+x\n*** Delete File: a.go\n*** End Patch"}, status: StatusAmbiguous},
		{name: "normalized duplicate path aliases", fields: map[string]any{"patch": "*** Begin Patch\n*** Add File: dir/../a.go\n+x\n*** Delete File: a.go\n*** End Patch"}, status: StatusAmbiguous},
		{name: "mixed separator duplicate path aliases", fields: map[string]any{"patch": "*** Begin Patch\n*** Add File: dir\\..\\a.go\n+x\n*** Delete File: a.go\n*** End Patch"}, status: StatusAmbiguous},
		{name: "duplicate aliases", fields: map[string]any{"command": valid, "patch": valid}, status: StatusAmbiguous},
		{name: "explicit path conflict", fields: map[string]any{"patch": valid, "path": "other.go"}, status: StatusAmbiguous},
		{name: "POSIX absolute path", fields: map[string]any{"patch": "*** Begin Patch\n*** Delete File: /etc/hosts\n*** End Patch"}, status: StatusInvalid},
		{name: "drive absolute path", fields: map[string]any{"patch": "*** Begin Patch\n*** Delete File: C:\\Windows\\win.ini\n*** End Patch"}, status: StatusInvalid},
		{name: "UNC absolute path", fields: map[string]any{"patch": "*** Begin Patch\n*** Delete File: \\\\server\\share\\file.txt\n*** End Patch"}, status: StatusInvalid},
		{name: "nul path", fields: map[string]any{"patch": "*** Begin Patch\n*** Add File: a\x00.go\n+x\n*** End Patch"}, status: StatusInvalid},
		{name: "path limit", fields: map[string]any{"patch": "*** Begin Patch\n*** Add File: " + strings.Repeat("a", maxScalarBytes+1) + "\n+x\n*** End Patch"}, status: StatusLimitExceeded},
		{name: "directive limit", fields: map[string]any{"patch": many.String()}, status: StatusLimitExceeded},
		{name: "payload limit", fields: map[string]any{"patch": "*** Begin Patch\n*** Add File: a.go\n+" + strings.Repeat("x", maxArgsJSONBytes) + "\n*** End Patch"}, status: StatusLimitExceeded},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			args, err := json.Marshal(test.fields)
			if err != nil {
				t.Fatal(err)
			}
			facts := Analyze(Input{Tool: "apply_patch", Args: args})
			if facts.Parse.Status != test.status || facts.Authoritative() ||
				len(facts.Commands) != 0 || len(facts.Paths) != 0 {
				t.Fatalf("facts = %#v", facts)
			}
		})
	}
}

func TestAnalyzeApplyPatchResolvesRelativeWindowsPath(t *testing.T) {
	args, err := json.Marshal(map[string]string{
		"command": "*** Begin Patch\n*** Add File: src\\new.go\n+package sample\n*** End Patch",
	})
	if err != nil {
		t.Fatal(err)
	}
	facts := Analyze(Input{
		Tool: "apply_patch", Args: args, CWD: `C:\workspace`,
		DialectHint: DialectPowerShell,
	})
	if !facts.Authoritative() || len(facts.Paths) != 1 ||
		facts.Paths[0].Resolved != "C:/workspace/src/new.go" ||
		facts.Paths[0].Access != PathAccessWrite {
		t.Fatalf("facts = %#v", facts)
	}
}

func TestAnalyzePatchFieldRequiresExactToolAndField(t *testing.T) {
	patch := "*** Begin Patch\n*** Add File: safe.go\n+safe\n*** End Patch"
	for _, test := range []struct {
		name, tool, field string
	}{
		{name: "generic patch alias", tool: "patch", field: "patch"},
		{name: "apply diff alias", tool: "apply_diff", field: "patch"},
		{name: "unreviewed field spelling", tool: "apply_patch", field: "patchtext"},
	} {
		t.Run(test.name, func(t *testing.T) {
			args, err := json.Marshal(map[string]string{test.field: patch})
			if err != nil {
				t.Fatal(err)
			}
			facts := Analyze(Input{Tool: test.tool, Args: args})
			if facts.Authoritative() || len(facts.Commands) != 0 || len(facts.Paths) != 0 {
				t.Fatalf("facts = %#v", facts)
			}
		})
	}
}

func patchFactsHavePath(
	facts Facts,
	value string,
	resolved string,
	access PathAccess,
) bool {
	for _, candidate := range facts.Paths {
		if candidate.Value == value && candidate.Resolved == resolved &&
			candidate.Access == access {
			return true
		}
	}
	return false
}
