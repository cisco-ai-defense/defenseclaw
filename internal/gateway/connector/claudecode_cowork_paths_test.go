// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// The plugin passes every supported path as a native argument. The ordinary
// path is the benign twin for the same generated handler.
func TestCoworkWindowsHookInvocationKeepsPathArgumentsLiteral(t *testing.T) {
	for _, name := range []string{"ordinary", "DC!Ops", "DC%Ops", "DC&Ops", "DC^Ops", "DC(Ops)"} {
		t.Run(name, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), name)
			bin := filepath.Join(root, "bin")
			if err := os.MkdirAll(bin, 0o700); err != nil {
				t.Fatal(err)
			}
			launcher := filepath.Join(bin, "defenseclaw-hook.exe")
			guard := filepath.Join(bin, "defenseclaw-hook-guard.exe")
			if err := os.WriteFile(guard, []byte("guard"), 0o700); err != nil {
				t.Fatal(err)
			}
			for _, event := range []string{"PreToolUse", "UserPromptSubmit"} {
				command, args := coworkWindowsHookInvocation(root, launcher, event)
				want := []string{"cowork-guard", root, launcher, event}
				if command != guard || !reflect.DeepEqual(args, want) {
					t.Fatalf("%s: command %q args %q, want native guard %q args %q", event, command, args, guard, want)
				}
			}
		})
	}
}

func TestCoworkWindowsGuardForUsesSmallExecutableInBothLayouts(t *testing.T) {
	root := t.TempDir()
	stable := filepath.Join(root, "HookRuntime", "defenseclaw-hook.exe")
	installed := filepath.Join(root, "Programs", "DefenseClaw", "bin", "defenseclaw-hook.exe")
	nativeGuard := filepath.Join(filepath.Dir(installed), "defenseclaw-hook-guard.exe")
	for _, path := range []string{stable, installed, nativeGuard} {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("fixture"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if got := coworkWindowsGuardFor(stable, stable, installed); got != nativeGuard {
		t.Fatalf("native guard = %q, want the small installed guard %q", got, nativeGuard)
	}
	if err := os.Remove(nativeGuard); err != nil {
		t.Fatal(err)
	}
	if got := coworkWindowsGuardFor(stable, stable, installed); got != "" {
		t.Fatalf("native layout without the small guard selected %q", got)
	}
	oneLine := filepath.Join(root, "bin", "defenseclaw-hook.exe")
	oneLineGuard := filepath.Join(filepath.Dir(oneLine), "defenseclaw-hook-guard.exe")
	if err := os.MkdirAll(filepath.Dir(oneLine), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(oneLineGuard, []byte("fixture"), 0o700); err != nil {
		t.Fatal(err)
	}
	if got := coworkWindowsGuardFor(oneLine, stable, installed); got != oneLineGuard {
		t.Fatalf("one-line guard = %q, want %q", got, oneLineGuard)
	}
	if err := os.Remove(oneLineGuard); err != nil {
		t.Fatal(err)
	}
	if got := coworkWindowsGuardFor(oneLine, stable, installed); got != "" {
		t.Fatalf("one-line layout without the small guard selected %q", got)
	}
}
