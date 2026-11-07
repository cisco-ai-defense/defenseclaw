// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterprisehooks

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

func TestGAP0669PurgeReportsAccountFileKeptWithManagedStateRemoved(t *testing.T) {
	skipIfRoot(t)
	home := newTestHome(t)
	dataDir := filepath.Join(home, ".defenseclaw")
	writePurgeTestFile(t, filepath.Join(dataDir, "personal.txt"), "account note")
	writePurgeTestFile(t, filepath.Join(dataDir, "session-facts.json"), "{}")
	writePurgeTestFile(t, filepath.Join(dataDir, "hooks", "codex-hook.sh"), "managed")

	summary, err := PurgeUserState(context.Background(), InstallOptions{
		UserHome: home, OwnerUID: os.Getuid(), OwnerGID: os.Getgid(), Registry: connector.NewDefaultRegistry(),
	})
	if err != nil || !summary.Data || summary.Kept || !slices.Contains(summary.KeptEntries, "personal.txt") {
		t.Fatalf("purge summary = %+v, %v", summary, err)
	}
	if got, err := os.ReadFile(filepath.Join(dataDir, "personal.txt")); err != nil || string(got) != "account note" {
		t.Fatalf("account file changed: %q, %v", got, err)
	}
	for _, path := range []string{"session-facts.json", filepath.Join("hooks", "codex-hook.sh")} {
		if _, err := os.Lstat(filepath.Join(dataDir, path)); !os.IsNotExist(err) {
			t.Errorf("managed entry %s stayed: %v", path, err)
		}
	}
}
