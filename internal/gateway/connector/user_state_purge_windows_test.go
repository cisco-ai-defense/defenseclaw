// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"os"
	"path/filepath"
	"testing"
)

// A read-only hook script or credential stayed after a Windows purge. Both
// go now, with the rest of the folder.
func TestPurgeUserStateInRootHandlesReadOnlyFiles(t *testing.T) {
	dataDir := t.TempDir()
	hooks := filepath.Join(dataDir, "hooks")
	if err := os.Mkdir(hooks, 0o700); err != nil {
		t.Fatal(err)
	}
	script, token := filepath.Join(hooks, "devin-hook.ps1"), filepath.Join(hooks, ".hook-devin.token")
	for path, body := range map[string]string{script: hookMarker + "5\r\n", token: "secret"} {
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, 0o400); err != nil {
			t.Fatal(err)
		}
	}
	root, err := os.OpenRoot(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := PurgeUserStateInRoot(root, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(token); !os.IsNotExist(err) {
		t.Fatalf("read-only credential stayed: %v", err)
	}
	if _, err := os.Lstat(script); !os.IsNotExist(err) {
		t.Fatalf("read-only hook script stayed: %v", err)
	}
	if _, err := os.Lstat(hooks); !os.IsNotExist(err) {
		t.Fatalf("the hooks folder stayed: %v", err)
	}
}
