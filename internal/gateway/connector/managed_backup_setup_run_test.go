// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testSetupRunNonce = "0123456789abcdef0123456789abcdef"

func announceTestSetupRun(t *testing.T, dataDir, connector, content string) {
	t.Helper()
	dir := filepath.Join(dataDir, "connector_backups", connector)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, managedSetupRunFile), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func recordedSetupRun(t *testing.T, dataDir, connector, logical string) string {
	t.Helper()
	b, err := loadManagedFileBackupPath(managedFileBackupPath(dataDir, connector, logical))
	if err != nil {
		t.Fatal(err)
	}
	return b.SetupRun
}

// The record of a registration names the setup command that announced a run
// while it recorded its output, so that command can tell its own registration
// from any other that published a record for the same file.
func TestManagedBackupPostHashCarriesTheAnnouncedSetupRun(t *testing.T) {
	root := t.TempDir()
	dataDir := filepath.Join(root, "data")
	target := filepath.Join(root, "config.toml")
	if err := os.WriteFile(target, []byte("a = 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := captureManagedFileBackup(dataDir, "codex", "config.toml", target); err != nil {
		t.Fatal(err)
	}
	if got := recordedSetupRun(t, dataDir, "codex", "config.toml"); got != "" {
		t.Fatalf("a record with no post hash carries run %q", got)
	}
	announceTestSetupRun(t, dataDir, "codex", testSetupRunNonce+"\n")
	if err := updateManagedFileBackupPostHashValue(dataDir, "codex", "config.toml", target, sha256Hex([]byte("a = 2\n"))); err != nil {
		t.Fatal(err)
	}
	if got := recordedSetupRun(t, dataDir, "codex", "config.toml"); got != testSetupRunNonce {
		t.Fatalf("record run = %q, want the announced %q", got, testSetupRunNonce)
	}
	// A later registration that nobody announced replaces the post hash and
	// the earlier run no longer owns the record.
	if err := os.Remove(filepath.Join(dataDir, "connector_backups", "codex", managedSetupRunFile)); err != nil {
		t.Fatal(err)
	}
	if err := updateManagedFileBackupPostHashValue(dataDir, "codex", "config.toml", target, sha256Hex([]byte("a = 3\n"))); err != nil {
		t.Fatal(err)
	}
	if got := recordedSetupRun(t, dataDir, "codex", "config.toml"); got != "" {
		t.Fatalf("an unannounced registration left run %q on the record", got)
	}
}

// Anything but a short lowercase hex string is not a run nonce.
func TestManagedSetupRunIgnoresWhatIsNotANonce(t *testing.T) {
	dataDir := t.TempDir()
	for name, content := range map[string]string{
		"empty":     "",
		"too short": "abc123\n",
		"not hex":   strings.Repeat("g", 32),
		"upper":     strings.ToUpper(testSetupRunNonce),
		"too long":  strings.Repeat("a", 65),
		"two lines": testSetupRunNonce + "\n" + testSetupRunNonce,
	} {
		announceTestSetupRun(t, dataDir, "openclaw", content)
		if got := managedSetupRun(dataDir, "openclaw"); got != "" {
			t.Errorf("%s: nonce %q", name, got)
		}
	}
	announceTestSetupRun(t, dataDir, "openclaw", testSetupRunNonce+"\n")
	if got := managedSetupRun(dataDir, "openclaw"); got != testSetupRunNonce {
		t.Errorf("a nonce with its newline read as %q", got)
	}
	if got := managedSetupRun(dataDir, "codex"); got != "" {
		t.Errorf("another connector read run %q", got)
	}
	// A directory (or any non-regular file) in its place is not read.
	other := t.TempDir()
	if err := os.MkdirAll(filepath.Join(other, "connector_backups", "openclaw", managedSetupRunFile), 0o700); err != nil {
		t.Fatal(err)
	}
	if got := managedSetupRun(other, "openclaw"); got != "" {
		t.Errorf("a directory read as nonce %q", got)
	}
}

// The OpenClaw registration records the run that announced itself, and the
// record of a registration with no announcement carries none.
func TestOpenClawRegistrationRecordsTheAnnouncedSetupRun(t *testing.T) {
	for _, announced := range []bool{true, false} {
		_, configPath, opts := openClawJSON5Fixture(t, t.TempDir())
		if err := os.WriteFile(configPath, []byte(openClawCombinedSpelling), 0o644); err != nil {
			t.Fatal(err)
		}
		want := ""
		if announced {
			announceTestSetupRun(t, opts.DataDir, "openclaw", testSetupRunNonce+"\n")
			want = testSetupRunNonce
		}
		if err := NewOpenClawConnector().Setup(context.Background(), opts); err != nil {
			t.Fatalf("announced=%v: %v", announced, err)
		}
		if got := recordedSetupRun(t, opts.DataDir, "openclaw", "openclaw.json"); got != want {
			t.Fatalf("announced=%v: record run = %q, want %q", announced, got, want)
		}
	}
}

// The read-back path (capture, merge, read the file back) is the one the
// OpenClaw registration takes, and it records the announced run too.
func TestManagedBackupReadBackRecordsTheAnnouncedSetupRun(t *testing.T) {
	root := t.TempDir()
	dataDir := filepath.Join(root, "data")
	target := filepath.Join(root, "openclaw.json")
	if err := os.WriteFile(target, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	announceTestSetupRun(t, dataDir, "openclaw", testSetupRunNonce+"\n")
	if err := captureManagedFileBackup(dataDir, "openclaw", "openclaw.json", target); err != nil {
		t.Fatal(err)
	}
	written := []byte("{\"plugins\":{}}\n")
	if err := atomicWriteFile(target, written, 0o600); err != nil { // The writer the connectors commit with.
		t.Fatal(err)
	}
	if err := updateManagedFileBackupPostHash(dataDir, "openclaw", "openclaw.json", target); err != nil {
		t.Fatal(err)
	}
	if got := recordedSetupRun(t, dataDir, "openclaw", "openclaw.json"); got != testSetupRunNonce {
		t.Fatalf("record run = %q, want %q", got, testSetupRunNonce)
	}
}
