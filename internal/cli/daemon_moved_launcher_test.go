// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// GAP-0732: after an account rename or a home move the defenseclaw launcher
// in ~/.local/bin points into the old home (or its venv entry point names the
// old interpreter). defenseclaw-gateway, a plain copy, still runs and must say
// to rerun the installer.
func TestMovedCLILauncherNote(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("install.sh links the CLI on Unix only")
	}
	bin := t.TempDir()
	link := filepath.Join(bin, "defenseclaw")
	if err := os.Symlink("/home/old-account/.defenseclaw/.venv/bin/defenseclaw", link); err != nil {
		t.Fatal(err)
	}
	if note := movedCLILauncherNoteIn(bin); !strings.Contains(note, "Rerun the DefenseClaw installer") {
		t.Fatalf("dangling launcher: note = %q", note)
	}
	entry := filepath.Join(t.TempDir(), "defenseclaw")
	if err := os.WriteFile(entry, []byte("#!/home/old-account/.defenseclaw/.venv/bin/python3\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(entry, link); err != nil {
		t.Fatal(err)
	}
	if note := movedCLILauncherNoteIn(bin); !strings.Contains(note, "/home/old-account/.defenseclaw/.venv/bin/python3") {
		t.Fatalf("stale interpreter: note = %q", note)
	}
	if err := os.WriteFile(entry, []byte("#!/bin/sh\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	if note := movedCLILauncherNoteIn(bin); note != "" {
		t.Fatalf("working launcher: note = %q, want none", note)
	}
}
