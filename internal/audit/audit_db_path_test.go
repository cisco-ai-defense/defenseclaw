// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestAuditDBTightenedFileModeNeverWidens(t *testing.T) {
	for _, test := range []struct {
		input os.FileMode
		want  os.FileMode
	}{
		{input: 0o777, want: 0o600},
		{input: 0o640, want: 0o600},
		{input: 0o440, want: 0o400},
		{input: 0o400, want: 0o400},
		{input: 0o200, want: 0o200},
		{input: 0o000, want: 0o000},
	} {
		got := tightenedAuditDBFileMode(test.input)
		if got != test.want {
			t.Errorf("tightened mode %04o = %04o, want %04o", test.input, got, test.want)
		}
		if got&^test.input.Perm() != 0 {
			t.Errorf("tightened mode %04o added permissions to %04o", got, test.input)
		}
	}
}

func TestHardenedAuditSQLitePreservesInMemoryContract(t *testing.T) {
	db, err := openHardenedAuditSQLite(":memory:", auditDBPathHooks{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.Exec(`CREATE TABLE memory_probe (id INTEGER PRIMARY KEY)`); err != nil {
		t.Fatal(err)
	}
}

func TestPrepareAuditDBRejectsEmptyAndDSNPaths(t *testing.T) {
	for _, test := range []struct {
		name string
		path string
		want string
	}{
		{name: "empty", path: " ", want: "path is required"},
		{name: "dsn delimiter", path: filepath.Join(t.TempDir(), "audit?mode=ro.db"), want: "DSN delimiter"},
	} {
		t.Run(test.name, func(t *testing.T) {
			prepared, err := prepareAuditDatabasePath(test.path, auditDBPathHooks{})
			if prepared != nil {
				prepared.close()
			}
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("prepare error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestHardenedAuditSQLiteCreatesOwnerOnlyPath(t *testing.T) {
	root := t.TempDir()
	parent := filepath.Join(root, "nested", "audit")
	path := filepath.Join(parent, "audit.db")
	db, err := openHardenedAuditSQLite(path, auditDBPathHooks{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	parentInfo, err := os.Stat(parent)
	if err != nil {
		t.Fatal(err)
	}
	if !auditDBModeMatches(parentInfo, 0o700) {
		t.Fatalf("new parent mode = %04o, want owner-only platform permissions", parentInfo.Mode().Perm())
	}
	fileInfo, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !auditDBModeMatches(fileInfo, 0o600) {
		t.Fatalf("new audit DB mode = %04o, want owner-only platform permissions", fileInfo.Mode().Perm())
	}
}

func TestPrepareAuditDBPermissionFailuresAreFatal(t *testing.T) {
	sentinel := errors.New("injected permission failure")
	t.Run("database file", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "audit.db")
		prepared, err := prepareAuditDatabasePath(path, auditDBPathHooks{
			chmodFile: func(*os.File, os.FileMode) error { return sentinel },
		})
		if prepared != nil {
			prepared.close()
		}
		if !errors.Is(err, sentinel) {
			t.Fatalf("file chmod error = %v, want injected failure", err)
		}
	})
	t.Run("new directory", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "new", "audit.db")
		prepared, err := prepareAuditDatabasePath(path, auditDBPathHooks{
			chmodPath: func(string, os.FileMode) error { return sentinel },
		})
		if prepared != nil {
			prepared.close()
		}
		if !errors.Is(err, sentinel) {
			t.Fatalf("directory chmod error = %v, want injected failure", err)
		}
	})
}

func TestPrepareAuditDBSecuresEveryStaleSQLiteSidecar(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.db")
	if err := os.WriteFile(path, []byte("database"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, suffix := range auditDBSQLiteSidecarSuffixes {
		sidecar := path + suffix
		content := []byte("confidential-" + suffix)
		if err := os.WriteFile(sidecar, content, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(sidecar, 0o644); err != nil {
			t.Fatal(err)
		}
	}

	prepared, err := prepareAuditDatabasePath(path, auditDBPathHooks{})
	if err != nil {
		t.Fatal(err)
	}
	prepared.close()
	for _, suffix := range auditDBSQLiteSidecarSuffixes {
		sidecar := path + suffix
		info, err := os.Stat(sidecar)
		if err != nil {
			t.Fatal(err)
		}
		if !auditDBModeMatches(info, 0o600) {
			t.Errorf("stale %s mode = %04o, want owner-only platform permissions", suffix, info.Mode().Perm())
		}
		content, err := os.ReadFile(sidecar)
		if err != nil {
			t.Fatal(err)
		}
		if string(content) != "confidential-"+suffix {
			t.Errorf("stale %s content changed during permission repair", suffix)
		}
	}
}

func TestPrepareAuditDBSidecarPermissionFailureIsFatal(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.db")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path+"-journal", []byte("pages"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path+"-journal", 0o644); err != nil {
		t.Fatal(err)
	}
	sentinel := errors.New("injected sidecar chmod failure")
	prepared, err := prepareAuditDatabasePath(path, auditDBPathHooks{
		chmodFile: func(candidate *os.File, mode os.FileMode) error {
			if strings.HasSuffix(candidate.Name(), "-journal") {
				return sentinel
			}
			return candidate.Chmod(mode)
		},
	})
	if prepared != nil {
		prepared.close()
	}
	if !errors.Is(err, sentinel) {
		t.Fatalf("sidecar chmod error = %v, want injected failure", err)
	}
}

func TestPrepareAuditDBSidecarReplacementCannotRedirectPermissionRepair(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "audit.db")
	sidecar := path + "-journal"
	displaced := sidecar + ".validated"
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sidecar, []byte("validated pages"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(sidecar, 0o644); err != nil {
		t.Fatal(err)
	}

	replaced := false
	prepared, err := prepareAuditDatabasePath(path, auditDBPathHooks{
		chmodFile: func(pinned *os.File, mode os.FileMode) error {
			if !strings.HasSuffix(pinned.Name(), "-journal") || replaced {
				return pinned.Chmod(mode)
			}
			replaced = true
			if err := os.Rename(sidecar, displaced); err != nil {
				return err
			}
			if err := os.WriteFile(sidecar, []byte("attacker replacement"), 0o600); err != nil {
				return err
			}
			if err := os.Chmod(sidecar, 0o644); err != nil {
				return err
			}
			// Permission repair is intentionally applied to the already-pinned
			// validated file, never to the replacement now at the pathname.
			return pinned.Chmod(mode)
		},
	})
	if prepared != nil {
		prepared.close()
	}
	if !replaced {
		t.Fatal("sidecar replacement hook did not execute")
	}
	if err == nil || !strings.Contains(err.Error(), "changed during secure open") {
		t.Fatalf("sidecar replacement error = %v", err)
	}
	replacementInfo, statErr := os.Stat(sidecar)
	if statErr != nil {
		t.Fatal(statErr)
	}
	if runtime.GOOS != "windows" && replacementInfo.Mode().Perm() != 0o644 {
		t.Fatalf("replacement mode = %04o, permission repair followed the pathname", replacementInfo.Mode().Perm())
	}
	displacedInfo, statErr := os.Stat(displaced)
	if statErr != nil {
		t.Fatal(statErr)
	}
	if !auditDBModeMatches(displacedInfo, 0o600) {
		t.Fatalf("pinned validated sidecar mode = %04o, want owner-only", displacedInfo.Mode().Perm())
	}
}

func TestPrepareAuditDBSidecarReplacementCannotRedirectPlatformACLRepair(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "audit.db")
	sidecar := path + "-journal"
	displaced := sidecar + ".validated"
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sidecar, []byte("validated pages"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := secureAuditDBPlatformPath(path, false); err != nil {
		t.Fatal(err)
	}
	if err := secureAuditDBPlatformPath(sidecar, false); err != nil {
		t.Fatal(err)
	}

	replaced := false
	prepared, err := prepareAuditDatabasePath(path, auditDBPathHooks{
		securePlatformFile: func(pinned *os.File, directory bool) error {
			if !strings.HasSuffix(pinned.Name(), "-journal") || replaced {
				return secureAuditDBPlatformFile(pinned, directory)
			}
			replaced = true
			if err := os.Rename(sidecar, displaced); err != nil {
				return err
			}
			if err := os.WriteFile(sidecar, []byte("attacker replacement"), 0o600); err != nil {
				return err
			}
			// On Windows this applies the protected DACL through the pinned
			// handle. On Unix it exercises the same handle-bound platform seam.
			return secureAuditDBPlatformFile(pinned, directory)
		},
	})
	if prepared != nil {
		prepared.close()
	}
	if !replaced {
		t.Fatal("sidecar platform-ACL replacement hook did not execute")
	}
	if err == nil || !strings.Contains(err.Error(), "changed during secure open") {
		t.Fatalf("sidecar platform-ACL replacement error = %v", err)
	}
	replacement, readErr := os.ReadFile(sidecar)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(replacement) != "attacker replacement" {
		t.Fatalf("replacement content changed through path-based ACL repair: %q", replacement)
	}
}

func TestHardenedAuditSQLiteRejectsLeafReplacementDuringOpen(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "audit.db")
	replacement := filepath.Join(directory, "replacement.db")
	if err := os.WriteFile(replacement, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	var symlinkErr error
	db, err := openHardenedAuditSQLite(path, auditDBPathHooks{
		beforeSQLiteOpen: func(candidate string) error {
			if err := os.Rename(candidate, candidate+".pinned"); err != nil {
				return err
			}
			symlinkErr = os.Symlink(replacement, candidate)
			return symlinkErr
		},
	})
	if db != nil {
		_ = db.Close()
	}
	if symlinkErr != nil {
		t.Skipf("symlinks are unavailable: %v", symlinkErr)
	}
	if err == nil || (!strings.Contains(err.Error(), "symbolic link") &&
		!strings.Contains(err.Error(), "changed during secure open") &&
		!strings.Contains(err.Error(), "Windows reparse point")) {
		t.Fatalf("replacement race error = %v", err)
	}
}

func TestHardenedAuditSQLiteCreatesOwnerOnlyWALAndSHM(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.db")
	db, err := openHardenedAuditSQLite(path, auditDBPathHooks{})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close() //nolint:errcheck
	if _, err := db.Exec(`CREATE TABLE sidecar_probe (id INTEGER PRIMARY KEY, value TEXT)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO sidecar_probe(value) VALUES ('confidential')`); err != nil {
		t.Fatal(err)
	}
	if err := secureAuditDBSQLiteSidecars(path, auditDBPathHooks{}); err != nil {
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
		if !auditDBModeMatches(info, 0o600) {
			t.Errorf("live %s mode = %04o, want owner-only platform permissions", suffix, info.Mode().Perm())
		}
	}
}

func assertAuditDBPathError(t *testing.T, path, want string) {
	t.Helper()
	db, err := openHardenedAuditSQLite(path, auditDBPathHooks{})
	if db != nil {
		_ = db.Close()
	}
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("openHardenedAuditSQLite(%q) error = %v, want %q", path, err, want)
	}
}
