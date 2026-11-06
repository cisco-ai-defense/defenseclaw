// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"testing"
	"time"
)

// This is the PowerShell tool form in the GAP-0534 evidence case. Its Bash
// recovery parse prints a call that can be parsed back to itself.
const gap0534Command = `Write-Output $(.\a[1]<#x#>); Remove-Item -Recurse -Force ~/.defenseclaw`
const gap0534OrdinaryCommand = `Write-Output $(.\a[1]<#x#>); Remove-Item -Recurse -Force ~/project/output`

func TestGAP0534RecoveredParseFixedPoint(t *testing.T) {
	home := t.TempDir()
	cwd := filepath.Join(home, "project")
	previousStack := debug.SetMaxStack(8 << 20)
	defer debug.SetMaxStack(previousStack)
	start := time.Now()
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	for range 8 {
		if reason := UnprovenProtectedWrite("0`@A>`", cwd, home); reason == "" {
			t.Fatal("unresolved recovered redirect lost its bound verdict")
		}
		if reason := UnprovenProtectedWrite(gap0534Command, cwd, home); reason != "shell-parse-bound" {
			t.Fatalf("recovered parse reason = %q, want proof bound", reason)
		}
		if reason := UnprovenProtectedWrite(gap0534OrdinaryCommand, cwd, home); reason != "shell-parse-unreached" {
			t.Fatalf("ordinary recovered parse reason = %q, want an unreached proof bound", reason)
		}
		if reason := ActionCommandDecision(gap0534OrdinaryCommand, cwd, home); reason != "" {
			t.Fatalf("ordinary command decision = %q, want none", reason)
		}
		payload, err := json.Marshal(map[string]any{
			"hook_event_name": "PreToolUse", "tool_name": "PowerShell", "cwd": cwd,
			"tool_input": map[string]string{"command": gap0534Command},
		})
		if err != nil {
			t.Fatal(err)
		}
		// Windows hookexec sends no Resolve write evidence. The bounded
		// parser check above still runs on every host.
		if hookWriteEvidenceHost() {
			if targets, ok := Decode(Resolve(payload)); !ok || targets[UnprovenReasonKey] != "shell-parse-bound" {
				t.Fatal("hook path resolver lost the unproven protected write")
			}
		}
	}
	runtime.ReadMemStats(&after)
	if used := after.TotalAlloc - before.TotalAlloc; used > 64<<20 {
		t.Fatalf("recovered parse allocated %d bytes", used)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("recovered parse took %s", elapsed)
	}
}

func TestGAP0534ResolvedProtectedTreeReach(t *testing.T) {
	home := t.TempDir()
	state := filepath.Join(home, ".defenseclaw")
	physical := filepath.Join(home, "outside")
	project := filepath.Join(home, "project")
	for _, dir := range []string{state, physical, project} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	protected := filepath.Join(physical, "rule.yaml")
	ordinary := filepath.Join(project, "output")
	for _, file := range []string{protected, ordinary} {
		if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(physical, filepath.Join(state, "policies")); err != nil {
		t.Skipf("directory links unavailable: %v", err)
	}
	alias := filepath.Join(home, "rule-alias")
	if err := os.Symlink(protected, alias); err != nil {
		t.Skipf("file links unavailable: %v", err)
	}
	memo := NewTargetMemo()
	for _, target := range []string{protected, alias} {
		if grade := ProtectedReach(target, home, memo); grade != GradeNamed {
			t.Errorf("protected tree target %s has grade %s", filepath.Base(target), grade)
		}
	}
	if grade := ProtectedReach(ordinary, home, memo); grade != GradeNone {
		t.Errorf("ordinary sibling has grade %s", grade)
	}
}

var gap0534BenchmarkReason string

func BenchmarkGAP0534RecoveredParse(b *testing.B) {
	home := b.TempDir()
	cwd := filepath.Join(home, "project")
	if err := os.MkdirAll(filepath.Join(home, ".defenseclaw"), 0o700); err != nil {
		b.Fatal(err)
	}
	for _, tc := range []struct{ name, command string }{
		{"protected", gap0534Command},
		{"ordinary", gap0534OrdinaryCommand},
	} {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				gap0534BenchmarkReason = UnprovenProtectedWrite(tc.command, cwd, home)
			}
		})
	}
}
