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
