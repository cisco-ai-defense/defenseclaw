// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

type rollForwardFixture struct {
	dataDir, binDir, gateway, recovery, target string
	helper                                     []byte
}

func digestLine(name string, data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]) + "  " + name + "\n"
}

// newRollForwardFixture is the state an older release roll-forward leaves
// (GAP-2521): the 1.0.5 gateway and installer folder are back, the hook-post
// helper beside the gateway is not.
func newRollForwardFixture(t *testing.T) rollForwardFixture {
	t.Helper()
	root := t.TempDir()
	f := rollForwardFixture{
		dataDir: filepath.Join(root, ".defenseclaw"),
		binDir:  filepath.Join(root, ".local", "bin"),
		helper:  []byte("hook-post 1.0.5 binary"),
	}
	f.gateway = filepath.Join(f.binDir, "defenseclaw-gateway")
	f.recovery = filepath.Join(f.dataDir, "installer", "defenseclaw-hook-post")
	f.target = filepath.Join(f.binDir, "defenseclaw-hook-post")
	gateway := []byte("gateway 1.0.5 binary")
	for _, dir := range []string{f.binDir, filepath.Dir(f.recovery)} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(f.gateway, gateway, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f.recovery, f.helper, 0o700); err != nil {
		t.Fatal(err)
	}
	record := digestLine("defenseclaw-gateway", gateway) + digestLine("defenseclaw-hook-post", f.helper) +
		digestLine("defenseclaw-acp", []byte("acp"))
	if err := os.WriteFile(filepath.Join(f.dataDir, "installer", "binaries.sha256"), []byte(record), 0o600); err != nil {
		t.Fatal(err)
	}
	return f
}

func TestARollForwardByAnOlderReleaseGetsTheHookPostHelperBack(t *testing.T) {
	f := newRollForwardFixture(t)
	restored := restorePerUserInstallerHelpersFor(f.dataDir, f.gateway)
	if len(restored) != 1 || restored[0] != "defenseclaw-hook-post" {
		t.Fatalf("restored = %v, want [defenseclaw-hook-post]", restored)
	}
	got, err := os.ReadFile(f.target)
	if err != nil || !bytes.Equal(got, f.helper) {
		t.Fatalf("helper beside the gateway = %q, %v; want the recorded copy", got, err)
	}
	info, err := os.Lstat(f.target)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o755 {
		t.Fatalf("helper mode = %v, %v; want a regular 0755 file", info.Mode(), err)
	}
	if _, err := os.Lstat(filepath.Join(f.binDir, "defenseclaw-acp")); !os.IsNotExist(err) {
		t.Fatalf("a binary with no installer copy was created: %v", err)
	}
	leftovers, _ := filepath.Glob(filepath.Join(f.binDir, ".defenseclaw-hook-post.restore-*"))
	if len(leftovers) != 0 {
		t.Fatalf("temporary files left: %v", leftovers)
	}
	if again := restorePerUserInstallerHelpersFor(f.dataDir, f.gateway); len(again) != 0 {
		t.Fatalf("second start restored %v again", again)
	}
}

func TestHelperRestoreNeverReplacesAFileBesideTheGateway(t *testing.T) {
	f := newRollForwardFixture(t)
	if err := os.WriteFile(f.target, []byte("other"), 0o755); err != nil {
		t.Fatal(err)
	}
	if restored := restorePerUserInstallerHelpersFor(f.dataDir, f.gateway); len(restored) != 0 {
		t.Fatalf("restored %v over an existing file", restored)
	}
	if got, _ := os.ReadFile(f.target); string(got) != "other" {
		t.Fatalf("existing file changed to %q", got)
	}
}

func TestHelperRestoreNeedsTheRecordedGatewayAndCopy(t *testing.T) {
	t.Run("another gateway", func(t *testing.T) {
		f := newRollForwardFixture(t)
		if err := os.WriteFile(f.gateway, []byte("gateway 1.0.2 binary"), 0o755); err != nil {
			t.Fatal(err)
		}
		if restored := restorePerUserInstallerHelpersFor(f.dataDir, f.gateway); len(restored) != 0 {
			t.Fatalf("restored %v for a gateway the record does not name", restored)
		}
	})
	t.Run("changed copy", func(t *testing.T) {
		f := newRollForwardFixture(t)
		if err := os.WriteFile(f.recovery, []byte("tampered"), 0o700); err != nil {
			t.Fatal(err)
		}
		if restored := restorePerUserInstallerHelpersFor(f.dataDir, f.gateway); len(restored) != 0 {
			t.Fatalf("restored %v from a copy with another digest", restored)
		}
	})
	t.Run("shared installer folder", func(t *testing.T) {
		f := newRollForwardFixture(t)
		if err := os.Chmod(filepath.Dir(f.recovery), 0o770); err != nil {
			t.Fatal(err)
		}
		if restored := restorePerUserInstallerHelpersFor(f.dataDir, f.gateway); len(restored) != 0 {
			t.Fatalf("restored %v from a group-writable folder", restored)
		}
	})
	t.Run("symlinked copy", func(t *testing.T) {
		f := newRollForwardFixture(t)
		realCopy := f.recovery + ".real"
		if err := os.Rename(f.recovery, realCopy); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(realCopy, f.recovery); err != nil {
			t.Fatal(err)
		}
		if restored := restorePerUserInstallerHelpersFor(f.dataDir, f.gateway); len(restored) != 0 {
			t.Fatalf("restored %v through a symlink", restored)
		}
	})
}
