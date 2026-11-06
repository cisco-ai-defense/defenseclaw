// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
