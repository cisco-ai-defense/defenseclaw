// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisepolicy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// rel-1-0-10:GAP-2221: a handler is DefenseClaw's own only when its command
// names the installed hook binary file itself. A fold twin of the hook path
// (a folder spelled with the Kelvin sign U+212A where the hook's folder has
// k) is another NTFS name; strings.EqualFold took it for the hook path, so
// it counted as owned whether it named another file or nothing.
func TestGAP2221FoldTwinOfTheHookPathIsNotOwned(t *testing.T) {
	root := t.TempDir()
	hook := filepath.Join(root, "kit", "defenseclaw-hook.exe")
	twin := filepath.Join(root, "\u212Ait", "defenseclaw-hook.exe")
	for _, f := range []string{hook, twin} {
		if err := os.MkdirAll(filepath.Dir(f), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(f, []byte(f), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	a, errA := os.Stat(hook)
	b, errB := os.Stat(twin)
	if errA != nil || errB != nil || os.SameFile(a, b) {
		t.Skip("this volume does not tell the Kelvin sign from k")
	}
	if !sameHookBinary("windows", hook, hook) || !sameHookBinary("windows", strings.ToUpper(hook), hook) {
		t.Fatal("the hook path itself, in any ASCII case, is not owned")
	}
	if sameHookBinary("windows", twin, hook) {
		t.Error("an existing fold twin of the hook path (another file) counted as owned")
	}
	_ = os.Remove(twin)
	if sameHookBinary("windows", twin, hook) {
		t.Error("a missing fold twin of the hook path counted as owned")
	}
}
