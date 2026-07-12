// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTightenedJudgeBodyFileModeNeverWidens(t *testing.T) {
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
		got := tightenedJudgeBodyFileMode(test.input)
		if got != test.want {
			t.Errorf("tightened mode %04o = %04o, want %04o", test.input, got, test.want)
		}
		if got&^test.input.Perm() != 0 {
			t.Errorf("tightened mode %04o added permissions to %04o", got, test.input)
		}
	}
}

func TestJudgeBodyDatabaseIdentityDetectsHardLinkAlias(t *testing.T) {
	directory := t.TempDir()
	auditPath := filepath.Join(directory, "audit.db")
	judgePath := filepath.Join(directory, "judge_bodies.db")
	if err := os.WriteFile(auditPath, []byte("identity"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(auditPath, judgePath); err != nil {
		t.Skipf("hard links are unavailable: %v", err)
	}
	if !sameJudgeBodyDatabaseFile(auditPath, judgePath) {
		t.Fatal("hard-link aliases were treated as distinct databases")
	}
	if !sameSQLitePath(auditPath, judgePath) {
		t.Fatal("cutover same-file guard did not reject hard-link aliases")
	}
	if sameJudgeBodyDatabaseFile(auditPath, filepath.Join(directory, "missing.db")) {
		t.Fatal("missing database was treated as an alias")
	}
}

func TestJudgeBodyStoreRejectsSQLiteDSNDelimiterInPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "judge?bodies.db")
	if _, err := NewJudgeBodyStore(path); err == nil || !strings.Contains(err.Error(), "DSN delimiter") {
		t.Fatalf("DSN-delimited path error = %v", err)
	}
}

func TestJudgeBodyStoreChmodFailuresAreFatal(t *testing.T) {
	sentinel := errors.New("injected chmod failure")
	t.Run("database file", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "judge_bodies.db")
		_, err := newJudgeBodyStoreWithPathHooks(path, false, judgeBodyPathHooks{
			chmodFile: func(*os.File, os.FileMode) error { return sentinel },
		})
		if !errors.Is(err, sentinel) {
			t.Fatalf("chmod error = %v, want injected failure", err)
		}
	})
	t.Run("new directory", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "new", "judge_bodies.db")
		_, err := newJudgeBodyStoreWithPathHooks(path, false, judgeBodyPathHooks{
			chmodPath: func(string, os.FileMode) error { return sentinel },
		})
		if !errors.Is(err, sentinel) {
			t.Fatalf("directory chmod error = %v, want injected failure", err)
		}
	})
}

func TestJudgeBodyStoreRejectsLeafReplacementDuringOpen(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "judge_bodies.db")
	replacement := filepath.Join(directory, "replacement.db")
	if err := os.WriteFile(replacement, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	var symlinkErr error
	_, err := newJudgeBodyStoreWithPathHooks(path, false, judgeBodyPathHooks{
		beforeSQLiteOpen: func(candidate string) error {
			if err := os.Rename(candidate, candidate+".pinned"); err != nil {
				return err
			}
			symlinkErr = os.Symlink(replacement, candidate)
			return symlinkErr
		},
	})
	if symlinkErr != nil {
		t.Skipf("symlinks are unavailable: %v", symlinkErr)
	}
	if err == nil {
		t.Fatal("database replacement race was accepted")
	}
	if !strings.Contains(err.Error(), "symbolic link") && !strings.Contains(err.Error(), "changed during secure open") {
		t.Fatalf("replacement race error = %v", err)
	}
}

func assertJudgeBodyStorePathError(t *testing.T, path, want string) {
	t.Helper()
	store, err := NewJudgeBodyStore(path)
	if store != nil {
		_ = store.Close()
	}
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("NewJudgeBodyStore(%q) error = %v, want %q", path, err, want)
	}
}
