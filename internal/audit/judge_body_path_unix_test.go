//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

type judgeBodyOwnerOverrideInfo struct {
	os.FileInfo
	stat syscall.Stat_t
}

func (info judgeBodyOwnerOverrideInfo) Sys() any { return &info.stat }

func TestJudgeBodyStoreRejectsUnsafeUnixPaths(t *testing.T) {
	t.Run("leaf symlink", func(t *testing.T) {
		directory := t.TempDir()
		target := filepath.Join(directory, "target.db")
		path := filepath.Join(directory, "judge_bodies.db")
		if err := os.WriteFile(target, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, path); err != nil {
			t.Skipf("symlinks are unavailable: %v", err)
		}
		assertJudgeBodyStorePathError(t, path, "symbolic link")
	})

	t.Run("parent symlink", func(t *testing.T) {
		directory := t.TempDir()
		realParent := filepath.Join(directory, "real")
		aliasParent := filepath.Join(directory, "alias")
		if err := os.Mkdir(realParent, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(realParent, aliasParent); err != nil {
			t.Skipf("symlinks are unavailable: %v", err)
		}
		assertJudgeBodyStorePathError(t, filepath.Join(aliasParent, "judge_bodies.db"), "symbolic link")
	})

	t.Run("non-regular leaf", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "judge_bodies.db")
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
		assertJudgeBodyStorePathError(t, path, "must be regular")
	})

	t.Run("group-writable parent", func(t *testing.T) {
		parent := filepath.Join(t.TempDir(), "unsafe")
		if err := os.Mkdir(parent, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(parent, 0o770); err != nil {
			t.Fatal(err)
		}
		defer os.Chmod(parent, 0o700) //nolint:errcheck
		assertJudgeBodyStorePathError(t, filepath.Join(parent, "judge_bodies.db"), "group- or other-writable")
	})

	t.Run("sticky world-writable immediate parent", func(t *testing.T) {
		parent := filepath.Join(t.TempDir(), "sticky")
		if err := os.Mkdir(parent, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := syscall.Chmod(parent, 0o1777); err != nil {
			t.Fatal(err)
		}
		defer os.Chmod(parent, 0o700) //nolint:errcheck
		info, err := os.Lstat(parent)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode()&os.ModeSticky == 0 {
			t.Fatalf("test fixture is not sticky: mode=%v", info.Mode())
		}
		assertJudgeBodyStorePathError(t, filepath.Join(parent, "judge_bodies.db"), "group- or other-writable")
	})

	t.Run("root sticky world-writable immediate parent", func(t *testing.T) {
		parent := string(os.PathSeparator) + "tmp"
		info, err := os.Stat(parent)
		if err != nil {
			t.Skipf("system temporary directory is unavailable: %v", err)
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 || info.Mode()&os.ModeSticky == 0 || info.Mode().Perm()&0o022 == 0 {
			t.Skipf("%s is not a root-owned writable sticky directory", parent)
		}
		assertJudgeBodyStorePathError(t, filepath.Join(parent, "judge_bodies.db"), "immediate database directory")
	})

	t.Run("other-writable leaf", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "judge_bodies.db")
		if err := os.WriteFile(path, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, 0o602); err != nil {
			t.Fatal(err)
		}
		assertJudgeBodyStorePathError(t, path, "group- or other-writable")
	})
}

func TestJudgeBodySQLiteSidecarsAreOwnerOnly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "judge_bodies.db")
	store, err := NewJudgeBodyStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close() //nolint:errcheck
	if err := store.InsertJudgeResponse(JudgeResponse{
		ID:        "sidecar-mode",
		Timestamp: time.Now().UTC(),
		Kind:      "test",
		Raw:       `{}`,
	}); err != nil {
		t.Fatal(err)
	}

	for _, suffix := range []string{"-wal", "-shm"} {
		info, err := os.Stat(path + suffix)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode().Perm(); got&0o077 != 0 {
			t.Fatalf("%s mode = %04o, want no group/other access", suffix, got)
		}
	}
}

func TestJudgeBodyStoreTightensStaleSQLiteWALBeforeReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "judge_bodies.db")
	first, err := NewJudgeBodyStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close() //nolint:errcheck
	if err := first.InsertJudgeResponse(JudgeResponse{
		ID: "stale-wal", Timestamp: time.Now().UTC(), Kind: "test", Raw: `{}`,
	}); err != nil {
		t.Fatal(err)
	}
	walPath := path + "-wal"
	if _, err := os.Stat(walPath); err != nil {
		t.Fatalf("expected WAL after write: %v", err)
	}
	if err := syscall.Chmod(walPath, 0o644); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(walPath); err != nil || info.Mode().Perm() != 0o644 {
		t.Fatalf("stale WAL fixture mode = %v, err=%v", info.Mode().Perm(), err)
	}

	second, err := NewJudgeBodyStore(path)
	if err != nil {
		t.Fatalf("reopen stale WAL: %v", err)
	}
	defer second.Close() //nolint:errcheck
	info, err := os.Stat(walPath)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("reopened WAL mode = %04o, want 0600", got)
	}
}

func TestJudgeBodyStoreRejectsSQLiteSidecarSymlink(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "judge_bodies.db")
	target := filepath.Join(directory, "attacker-wal")
	if err := os.WriteFile(target, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path+"-wal"); err != nil {
		t.Skipf("symlinks are unavailable: %v", err)
	}
	assertJudgeBodyStorePathError(t, path, "SQLite sidecar -wal")
}

func TestJudgeBodyStoreTightensExistingFileWithoutWidening(t *testing.T) {
	path := filepath.Join(t.TempDir(), "judge_bodies.db")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}
	store, err := NewJudgeBodyStore(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("existing database mode = %04o, want tightened 0600", got)
	}
}

func TestJudgeBodyStoreRejectsPermissionChangeDuringOpen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "judge_bodies.db")
	store, err := newJudgeBodyStoreWithPathHooks(path, false, judgeBodyPathHooks{
		beforeSQLiteOpen: func(candidate string) error {
			return os.Chmod(candidate, 0o644)
		},
	})
	if store != nil {
		_ = store.Close()
	}
	if err == nil || !strings.Contains(err.Error(), "permissions changed during secure open") {
		t.Fatalf("permission replacement error = %v", err)
	}
}

func TestJudgeBodyStoreRejectsUntrustedOwnerWhenChownAvailable(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("changing file ownership requires root")
	}
	path := filepath.Join(t.TempDir(), "judge_bodies.db")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(path, 65534, -1); err != nil {
		t.Skipf("chown is unavailable: %v", err)
	}
	assertJudgeBodyStorePathError(t, path, "untrusted owner")
}

func TestJudgeBodyUnixTrustRejectsSyntheticUntrustedOwner(t *testing.T) {
	path := filepath.Join(t.TempDir(), "judge_bodies.db")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatal("file ownership metadata is unavailable")
	}
	override := judgeBodyOwnerOverrideInfo{FileInfo: info, stat: *stat}
	override.stat.Uid = uint32(os.Geteuid() + 1)
	if err := validateJudgeBodyPlatformTrust(path, override, false, true); err == nil || !strings.Contains(err.Error(), "untrusted owner") {
		t.Fatalf("synthetic owner error = %v", err)
	}
}
