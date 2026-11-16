//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
)

// The per-user worker tells the root parent when an editor's extensions
// folder was too crowded to read, and the parent keeps that as an
// incomplete scan (GAP-1077); a normal folder adds nothing.
func TestEnterpriseHooksDiscoverKeepsAnUnlistedExtensionsFolder(t *testing.T) {
	for _, tc := range []struct {
		name       string
		entries    int
		incomplete bool
	}{
		{name: "crowded folder", entries: 4097, incomplete: true},
		{name: "normal folder", entries: 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			useEnterpriseHookWorkerHelper(t, "ok")
			restore := enterpriseHookWorkerRunner
			enterpriseHookWorkerRunner = runEnterpriseHookWorker
			t.Cleanup(func() { enterpriseHookWorkerRunner = restore })
			home := filepath.Clean(t.TempDir())
			root := filepath.Join(home, ".vscode", "extensions")
			for i := 0; i < tc.entries; i++ {
				if err := os.MkdirAll(filepath.Join(root, fmt.Sprintf("pad.ext-%05d", i)), 0o755); err != nil {
					t.Fatal(err)
				}
			}
			found, err := enterpriseHooksEnumerateDiscoverSurfaces(context.Background(),
				unixidentity.Account{Name: "self", UID: os.Getuid(), GID: os.Getgid(), Home: home}, []string{"claudecode"})
			if err != nil {
				t.Fatal(err)
			}
			got := false
			for _, install := range found.PrivateInstalls {
				if install.Connector == "claudecode" && install.Incomplete && install.Skipped == enterprisehooks.PrivateInstallSkippedExtensions {
					got = true
				}
			}
			if got != tc.incomplete {
				t.Fatalf("extensions-folder incomplete = %v, want %v: %+v", got, tc.incomplete, found.PrivateInstalls)
			}
		})
	}
}
