//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A port that already matches is checked like a port that does not
// (GAP-0053 REVIEW-1 MF1). The stow layout (a link to the account's own
// private dotfiles) stays a no-op; a link that leads to a file or folder
// another account can write is not accepted as it stands.
func TestSetOpenCodeServicePortChecksWhereAMatchingFileLives(t *testing.T) {
	const port = 25001
	type layout struct {
		name     string
		linkAt   string // "config" links ~/.config, "opencode" links ~/.config/opencode
		fileMode os.FileMode
		dirMode  os.FileMode
		wantNoOp bool
	}
	for _, c := range []layout{
		{"linked config folder, private target", "config", 0o600, 0o700, true},
		{"linked opencode folder, private target", "opencode", 0o600, 0o700, true},
		{"linked config folder, shared file", "config", 0o666, 0o700, false},
		{"linked opencode folder, shared file", "opencode", 0o666, 0o700, false},
		{"linked config folder, shared target folder", "config", 0o600, 0o777, false},
		{"linked opencode folder, shared target folder", "opencode", 0o600, 0o777, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			home := t.TempDir()
			target := filepath.Join(home, "dotfiles")
			real := filepath.Join(target, "opencode")
			if c.linkAt == "opencode" {
				real = target
			}
			if err := os.MkdirAll(real, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(real, c.dirMode); err != nil {
				t.Fatal(err)
			}
			file := filepath.Join(real, "service.json")
			if err := os.WriteFile(file, []byte(`{"port":25001}`), c.fileMode); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(file, c.fileMode); err != nil {
				t.Fatal(err)
			}
			if c.linkAt == "config" {
				if err := os.Symlink(target, filepath.Join(home, ".config")); err != nil {
					t.Skip(err)
				}
			} else {
				if err := os.MkdirAll(filepath.Join(home, ".config"), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, filepath.Join(home, ".config", "opencode")); err != nil {
					t.Skip(err)
				}
			}
			result, err := SetOpenCodeServicePort(home, port)
			if c.wantNoOp {
				if err != nil || result.Changed || result.Port != port {
					t.Fatalf("a private linked file was not accepted: %+v %v", result, err)
				}
				return
			}
			if err == nil && !result.Changed {
				t.Fatalf("a matching file another account can write was accepted as it stands: %+v", result)
			}
			if c.linkAt == "opencode" && err == nil {
				t.Fatalf("a link in place of the opencode folder was written through: %+v", result)
			}
		})
	}
}

func TestSetOpenCodeServicePortReplacesASharedWritableMatchingFile(t *testing.T) {
	const port = 25001
	for _, mode := range []os.FileMode{0o666, 0o664, 0o622} {
		home := t.TempDir()
		path := OpenCodeServiceConfigPath(home)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(`{"port":25001,"password":"p"}`), mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		result, err := SetOpenCodeServicePort(home, port)
		if err != nil || !result.Changed || result.Port != port {
			t.Fatalf("mode %o: %+v %v", mode, result, err)
		}
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("mode %o: file mode after the call %v %v", mode, info, err)
		}
		if data, _ := os.ReadFile(path); !strings.Contains(string(data), `"password": "p"`) || !strings.Contains(string(data), `"port": 25001`) {
			t.Fatalf("mode %o: keys lost: %s", mode, data)
		}
	}
}

// Benign twin: an ordinary private matching file (0600 and 0644, the modes
// OpenCode creates) stays untouched.
func TestSetOpenCodeServicePortLeavesAnOrdinaryMatchingFile(t *testing.T) {
	for _, mode := range []os.FileMode{0o600, 0o644} {
		home := t.TempDir()
		path := OpenCodeServiceConfigPath(home)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(`{"port":25001}`), mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		before, _ := os.Stat(path)
		result, err := SetOpenCodeServicePort(home, 25001)
		after, _ := os.Stat(path)
		if err != nil || result.Changed || result.Port != 25001 || !os.SameFile(before, after) || after.Mode().Perm() != mode {
			t.Fatalf("mode %o: %+v %v", mode, result, err)
		}
	}
}
