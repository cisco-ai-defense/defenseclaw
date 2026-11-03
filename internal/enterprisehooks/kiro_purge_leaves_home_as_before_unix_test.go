//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

// p0-round GAP-0902: a managed uninstall --purge of an account the guardian
// enrolled for Kiro in a home where Kiro never ran leaves that home as it
// was before the enrollment: no empty ~/.kiro, ~/.kiro/hooks,
// ~/.kiro/agents or ~/.kiro/settings, and no '{}' ~/.kiro/settings/cli.json.
func TestManagedKiroRemovalAndPurgeLeaveTheHomeAsBefore(t *testing.T) {
	skipIfRoot(t)
	t.Setenv("DEFENSECLAW_ALLOW_HOOK_CONTRACT_DRIFT", "")
	setStandaloneProfileForTest(t, true)
	home := newTestHome(t)
	opts := kiroStandaloneInstallOptions(home, "kiro-cli 2.27.1")
	if _, err := Install(context.Background(), opts); err != nil {
		t.Fatalf("install kiro: %v", err)
	}
	if _, err := os.Stat(filepath.Join(home, ".kiro", "settings", "cli.json")); err != nil {
		t.Fatalf("the install did not select the managed agent: %v", err)
	}
	// The guardian reconciles the row again before the uninstall.
	if _, err := Install(context.Background(), opts); err != nil {
		t.Fatalf("repair kiro: %v", err)
	}
	if err := RemoveUserHooks(context.Background(), opts); err != nil {
		t.Fatalf("RemoveUserHooks: %v", err)
	}
	if _, err := PurgeUserState(context.Background(), opts); err != nil {
		t.Fatalf("PurgeUserState: %v", err)
	}
	var left []string
	_ = filepath.WalkDir(home, func(path string, entry fs.DirEntry, err error) error {
		if path != home {
			left = append(left, path)
		}
		return nil
	})
	if len(left) != 0 {
		t.Fatalf("the purge left what the enrollment created: %v", left)
	}
}
