// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterprisehooks

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// GAP-2015: a 1.0.4 per-user upgrade saved the user's edited OmniGent module
// in connector_backups/omnigent and told them to copy back what they need.
// The managed purge deleted it with the rest of connector_backups. It now
// moves the OpenHands/OmniGent backup folders beside the data folder (as the
// OSS uninstall does) and says where.
func TestPurgeUserStateKeepsTheRemovedConnectorBackups(t *testing.T) {
	skipIfRoot(t)
	home := newTestHome(t)
	dataDir := filepath.Join(home, ".defenseclaw")
	edited := "connector_backups/omnigent/defenseclaw_omnigent_policy.py.edited-ae793da7fbcd2b16"
	writePurgeTestFile(t, filepath.Join(dataDir, "config.yaml"), "gateway: {}\n")
	writePurgeTestFile(t, filepath.Join(dataDir, edited), "# my edit\n")
	writePurgeTestFile(t, filepath.Join(dataDir, "connector_backups/openhands/hooks.json.edited-01"), "{}\n")
	// An earlier purge already kept an omnigent folder: the new one gets
	// its own name, nothing is replaced.
	earlier := filepath.Join(home, ".defenseclaw-removed-connector-backups", "omnigent", "old")
	writePurgeTestFile(t, earlier, "earlier\n")
	summary, err := PurgeUserState(context.Background(), InstallOptions{
		UserHome: home, OwnerUID: os.Getuid(), OwnerGID: os.Getgid(), Registry: connector.NewDefaultRegistry(),
	})
	if err != nil {
		t.Fatalf("PurgeUserState: %v", err)
	}
	if !summary.Data {
		t.Fatalf("summary = %+v, want the data purged", summary)
	}
	if _, err := os.Lstat(dataDir); !os.IsNotExist(err) {
		t.Fatalf("~/.defenseclaw stayed: %v", err)
	}
	root := filepath.Join(home, ".defenseclaw-removed-connector-backups")
	want := []string{filepath.Join(root, "omnigent-2"), filepath.Join(root, "openhands")}
	if len(summary.KeptRemovedConnectorBackups) != 2 || summary.KeptRemovedConnectorBackups[0] != want[0] || summary.KeptRemovedConnectorBackups[1] != want[1] {
		t.Fatalf("kept = %v, want %v", summary.KeptRemovedConnectorBackups, want)
	}
	if got, err := os.ReadFile(filepath.Join(want[0], filepath.Base(edited))); err != nil || string(got) != "# my edit\n" {
		t.Fatalf("the edited copy was not kept: %q %v", got, err)
	}
	if got, err := os.ReadFile(earlier); err != nil || string(got) != "earlier\n" {
		t.Fatalf("the earlier kept folder changed: %q %v", got, err)
	}
	// A machine purge makes no per-user backup (GAP-0727), so the copies
	// above are the only place the removed-connector backups go.
	if backups, _ := filepath.Glob(filepath.Join(home, ".defenseclaw-backup-*")); len(backups) != 0 {
		t.Fatalf("the purge made a per-user backup: %v", backups)
	}
}
