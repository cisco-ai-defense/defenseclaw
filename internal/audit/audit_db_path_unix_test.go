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
)

type auditDBOwnerOverrideInfo struct {
	os.FileInfo
	stat syscall.Stat_t
}

func (info auditDBOwnerOverrideInfo) Sys() any { return &info.stat }

func TestAuditDBRejectsUnsafeUnixPaths(t *testing.T) {
	t.Run("leaf symlink", func(t *testing.T) {
		directory := t.TempDir()
		target := filepath.Join(directory, "target.db")
		path := filepath.Join(directory, "audit.db")
		if err := os.WriteFile(target, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, path); err != nil {
			t.Skipf("symlinks are unavailable: %v", err)
		}
		assertAuditDBPathError(t, path, "symbolic link")
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
		assertAuditDBPathError(t, filepath.Join(aliasParent, "audit.db"), "symbolic link")
	})

	t.Run("non-regular leaf", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "audit.db")
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
		assertAuditDBPathError(t, path, "must be regular")
	})

	t.Run("group-writable immediate parent", func(t *testing.T) {
		parent := filepath.Join(t.TempDir(), "unsafe")
		if err := os.Mkdir(parent, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(parent, 0o770); err != nil {
			t.Fatal(err)
		}
		defer os.Chmod(parent, 0o700) //nolint:errcheck
		assertAuditDBPathError(t, filepath.Join(parent, "audit.db"), "group- or other-writable")
	})

	t.Run("mutable ancestor", func(t *testing.T) {
		root := t.TempDir()
		ancestor := filepath.Join(root, "shared")
		parent := filepath.Join(ancestor, "defenseclaw")
		if err := os.Mkdir(ancestor, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(parent, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(ancestor, 0o770); err != nil {
			t.Fatal(err)
		}
		defer os.Chmod(ancestor, 0o700) //nolint:errcheck
		assertAuditDBPathError(t, filepath.Join(parent, "audit.db"), "group- or other-writable")
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
		assertAuditDBPathError(t, filepath.Join(parent, "audit.db"), "group- or other-writable")
	})

	t.Run("other-writable leaf", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "audit.db")
		if err := os.WriteFile(path, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, 0o602); err != nil {
			t.Fatal(err)
		}
		assertAuditDBPathError(t, path, "group- or other-writable")
	})
}

func TestAuditDBAllowsRootStickyAncestorWithOwnerOnlyParent(t *testing.T) {
	root := string(os.PathSeparator) + "tmp"
	info, err := os.Stat(root)
	if err != nil {
		t.Skipf("system temporary directory is unavailable: %v", err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || info.Mode()&os.ModeSticky == 0 || info.Mode().Perm()&0o022 == 0 {
		t.Skipf("%s is not a root-owned writable sticky directory", root)
	}
	parent, err := os.MkdirTemp(root, "defenseclaw-audit-path-")
	if err != nil {
		t.Skipf("cannot create owner-only child in %s: %v", root, err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(parent) })
	if err := os.Chmod(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	db, err := openHardenedAuditSQLite(filepath.Join(parent, "audit.db"), auditDBPathHooks{})
	if err != nil {
		t.Fatalf("root sticky ancestor with safe parent was rejected: %v", err)
	}
	_ = db.Close()
}

func TestAuditDBRejectsSQLiteSidecarSymlinks(t *testing.T) {
	for _, suffix := range auditDBSQLiteSidecarSuffixes {
		t.Run(suffix, func(t *testing.T) {
			directory := t.TempDir()
			path := filepath.Join(directory, "audit.db")
			target := filepath.Join(directory, "attacker-sidecar")
			if err := os.WriteFile(path, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(target, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, path+suffix); err != nil {
				t.Skipf("symlinks are unavailable: %v", err)
			}
			prepared, err := prepareAuditDatabasePath(path, auditDBPathHooks{})
			if prepared != nil {
				prepared.close()
			}
			if err == nil || !strings.Contains(err.Error(), "SQLite sidecar "+suffix) {
				t.Fatalf("sidecar symlink error = %v", err)
			}
		})
	}
}

func TestAuditDBTightensExistingGroupReadableFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.db")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}
	prepared, err := prepareAuditDatabasePath(path, auditDBPathHooks{})
	if err != nil {
		t.Fatal(err)
	}
	prepared.close()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("existing audit DB mode = %04o, want tightened 0600", got)
	}
}

func TestHardenedAuditSQLiteRejectsPermissionChangeDuringOpen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.db")
	db, err := openHardenedAuditSQLite(path, auditDBPathHooks{
		beforeSQLiteOpen: func(candidate string) error { return os.Chmod(candidate, 0o644) },
	})
	if db != nil {
		_ = db.Close()
	}
	if err == nil || !strings.Contains(err.Error(), "permissions changed during secure open") {
		t.Fatalf("permission race error = %v", err)
	}
}

func TestAuditDBRejectsUntrustedOwnerWhenChownAvailable(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("changing file ownership requires root")
	}
	path := filepath.Join(t.TempDir(), "audit.db")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(path, 65534, -1); err != nil {
		t.Skipf("chown is unavailable: %v", err)
	}
	assertAuditDBPathError(t, path, "untrusted owner")
}

func TestAuditDBUnixTrustRejectsSyntheticUntrustedOwner(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.db")
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
	override := auditDBOwnerOverrideInfo{FileInfo: info, stat: *stat}
	override.stat.Uid = uint32(os.Geteuid() + 1)
	err = validateAuditDBPlatformTrust(path, override, false, true)
	if err == nil || !strings.Contains(err.Error(), "untrusted owner") {
		t.Fatalf("synthetic owner error = %v", err)
	}
}
