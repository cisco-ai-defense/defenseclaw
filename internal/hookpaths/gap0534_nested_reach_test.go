// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestGAP0534NestedProtectedTreeReach(t *testing.T) {
	home := t.TempDir()
	state := filepath.Join(home, ".defenseclaw")
	outside := filepath.Join(home, "outside")
	for _, dir := range []string{filepath.Join(state, "policies"), outside} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	protected := filepath.Join(outside, "rule.yaml")
	ordinary := filepath.Join(home, "ordinary.yaml")
	for _, file := range []string{protected, ordinary} {
		if err := os.WriteFile(file, []byte("x"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	nested := filepath.Join(state, "policies", "relocated")
	if err := os.Symlink(outside, nested); err != nil {
		t.Fatal(err)
	}
	pending := filepath.Join(home, "pending-tree")
	if err := os.Symlink(pending, filepath.Join(state, "policies", "pending")); err != nil {
		t.Fatal(err)
	}
	hard := filepath.Join(home, "rule-hardlink")
	if err := os.Link(protected, hard); err != nil {
		t.Fatal(err)
	}
	for _, row := range []struct {
		name, target string
		want         Grade
	}{
		{"lexical", filepath.Join(nested, "rule.yaml"), GradeNamed},
		{"physical", protected, GradeNamed},
		{"physical-new", filepath.Join(outside, "new-rule.yaml"), GradeNamed},
		{"pending-tree-new", filepath.Join(pending, "new-rule.yaml"), GradeNamed},
		{"hardlink", hard, GradeNamed},
		{"ordinary", ordinary, GradeNone},
	} {
		t.Run(row.name, func(t *testing.T) {
			got := ProtectedReach(row.target, home, NewTargetMemo())
			if got != row.want {
				t.Errorf("grade = %v, want %v", got, row.want)
			}
		})
	}
}

func TestGAP0534RecoveredTextScanBeyondEarlierLimit(t *testing.T) {
	home := t.TempDir()
	cwd := filepath.Join(home, "project")
	state := filepath.Join(home, ".defenseclaw")
	for _, dir := range []string{cwd, state} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, quoted := range []bool{false, true} {
		name := "words"
		count := 520
		if quoted {
			name = "quoted"
			count = 260
		}
		t.Run(name, func(t *testing.T) {
			var text strings.Builder
			text.WriteString("Set-Content -Path ~/project/output -Value x #")
			for i := 0; i < count; i++ {
				word := fmt.Sprintf("ordinary%d", i)
				if quoted {
					word = "'" + word + "'"
				}
				text.WriteByte(' ')
				text.WriteString(word)
			}
			if protectedReachFromTextWithState(text.String(), cwd, home, state) {
				t.Fatal("ordinary text graded as protected")
			}
			text.WriteString("; Set-Content -Path ~/.defenseclaw/config.yaml -Value x")
			if !protectedReachFromTextWithState(text.String(), cwd, home, state) {
				t.Fatal("protected name after ordinary text was not reached")
			}
		})
	}
}

func TestGAP0534LargeRecoveredTextBounded(t *testing.T) {
	home := t.TempDir()
	cwd := filepath.Join(home, "project")
	state := filepath.Join(home, ".defenseclaw")
	for _, dir := range []string{cwd, state} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	var text strings.Builder
	text.WriteString("Write-Output $(.\\a[1]<#x#>); Set-Content -Path ~/project/output -Value x #")
	for i := 0; i < 50000; i++ {
		fmt.Fprintf(&text, " ordinary%d", i)
	}
	started := time.Now()
	if protectedReachFromTextWithStatePrepared(text.String(), cwd, home, state, nil, filepath.Join(home, ".ssh"), NewTargetMemo()) {
		t.Fatal("ordinary text graded as protected")
	}
	if elapsed := time.Since(started); elapsed > 3500*time.Millisecond {
		t.Errorf("ordinary recovery scan took %v, exceeding the hook answer window", elapsed)
	}
	text.WriteString("; Set-Content -Path ~/.defenseclaw/config.yaml -Value x")
	if !protectedReachFromTextWithStatePrepared(text.String(), cwd, home, state, nil, filepath.Join(home, ".ssh"), NewTargetMemo()) {
		t.Fatal("protected name after ordinary text was not reached")
	}
}

func TestGAP0534BatchedMissingLeavesKeepNamedAlias(t *testing.T) {
	home := t.TempDir()
	cwd := filepath.Join(home, "project")
	state := filepath.Join(home, ".defenseclaw")
	for _, dir := range []string{cwd, state} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(filepath.Join(cwd, "linked-config"), filepath.Join(state, "config.yaml")); err != nil {
		t.Fatal(err)
	}
	var text strings.Builder
	text.WriteString("Set-Content -Path ~/project/output -Value x #")
	for i := 0; i < 1000; i++ {
		fmt.Fprintf(&text, " ordinary%d", i)
	}
	check := func(command string, want bool) {
		t.Helper()
		got := protectedReachFromTextWithStatePrepared(command, cwd, home, state, nil, filepath.Join(home, ".ssh"), NewTargetMemo())
		if got != want {
			t.Errorf("protected reach = %t, want %t", got, want)
		}
	}
	ordinary := text.String()
	check(ordinary, false)
	check(ordinary+"; Set-Content -Path linked-config -Value x", true)
	check(ordinary+"; Set-Content -Path "+filepath.Join(state, "policies")+" -Value x", true)
}
