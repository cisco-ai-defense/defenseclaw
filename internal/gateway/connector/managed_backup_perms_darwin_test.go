// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package connector

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

func TestWriteManagedFileBackupDarwinRemovesDirectoryAndFileAllowACLs(t *testing.T) {
	dataDir := t.TempDir()
	backupPath := managedFileBackupPath(dataDir, "opencode", "config")
	connectorDir := filepath.Dir(backupPath)
	backupRoot := filepath.Dir(connectorDir)
	if err := os.MkdirAll(connectorDir, 0o700); err != nil {
		t.Fatalf("mkdir managed backup fixture: %v", err)
	}

	backup := managedFileBackup{
		Version:        managedBackupVersion,
		Connector:      "opencode",
		LogicalName:    "config",
		Path:           filepath.Join(dataDir, "defenseclaw.js"),
		PristineSHA256: managedBackupMissingHash,
	}
	body, err := json.MarshalIndent(backup, "", "  ")
	if err != nil {
		t.Fatalf("marshal managed backup fixture: %v", err)
	}
	if err := os.WriteFile(backupPath, append(body, '\n'), 0o600); err != nil {
		t.Fatalf("seed matching managed backup: %v", err)
	}

	addManagedBackupDarwinACL(t, backupRoot, "everyone allow add_file,add_subdirectory,delete_child")
	addManagedBackupDarwinACL(t, connectorDir, "everyone allow add_file,add_subdirectory,delete_child")
	addManagedBackupDarwinACL(t, backupPath, "everyone allow read")

	// The pre-existing bytes and POSIX mode already match. The old Darwin
	// atomic writer returned early here and left every extended ACL intact.
	if err := writeManagedFileBackup(backupPath, backup); err != nil {
		t.Fatalf("writeManagedFileBackup: %v", err)
	}
	if err := safefile.ValidatePrivateDirectory(backupRoot); err != nil {
		t.Fatalf("managed backup root is not private: %v", err)
	}
	if err := safefile.ValidatePrivateDirectory(connectorDir); err != nil {
		t.Fatalf("managed connector backup directory is not private: %v", err)
	}
	if err := safefile.ValidatePrivateFile(backupPath); err != nil {
		t.Fatalf("managed backup authority is not private: %v", err)
	}
}

func TestEnsureManagedBackupAuthorityDirsDarwinRejectsUnexpectedTree(t *testing.T) {
	unexpectedRoot := filepath.Join(t.TempDir(), "operator-state")
	connectorDir := filepath.Join(unexpectedRoot, "opencode")
	err := ensureManagedBackupAuthorityDirs(connectorDir)
	if err == nil || !strings.Contains(err.Error(), "outside the connector_backups tree") {
		t.Fatalf("ensureManagedBackupAuthorityDirs error = %v, want tree refusal", err)
	}
	if _, statErr := os.Stat(unexpectedRoot); !os.IsNotExist(statErr) {
		t.Fatalf("unexpected root was mutated before refusal: %v", statErr)
	}
}

func addManagedBackupDarwinACL(t *testing.T, path, entry string) {
	t.Helper()
	cmd := exec.Command("/bin/chmod", "+a", entry, path)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("add macOS ACL to %s: %v: %s", path, err, output)
	}
	t.Cleanup(func() { _ = exec.Command("/bin/chmod", "-N", path).Run() })
}
