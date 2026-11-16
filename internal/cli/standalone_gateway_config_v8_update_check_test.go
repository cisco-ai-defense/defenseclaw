// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"strings"
	"testing"
)

// rel-1-0-2 GAP-0145, Windows half (L-ewin-J5-023): Setup's config check
// (the standalone gateway config check) refused a config_version 8 candidate
// with the top-level update_check the 1.0.x CLI wrote, which the v9 migration
// moves to update.check. It checks the candidate as the Linux and macOS
// lifecycle does now; another unknown key is still refused.
func TestStandaloneGatewayConfigCheckAcceptsAV8UpdateCheck(t *testing.T) {
	dataDir := t.TempDir()
	withKey := strings.Replace(standaloneGatewayCheckConfig, "config_version: 8\n", "config_version: 8\nupdate_check: false\n", 1)
	if err := validateStandaloneGatewayConfig(writeStandaloneGatewayCheckConfig(t, withKey), dataDir, ""); err != nil {
		t.Fatalf("a v8 candidate with update_check: false was refused: %v", err)
	}
	unknown := strings.Replace(withKey, "update_check: false\n", "update_check: false\nnot_a_setting: 1\n", 1)
	if err := validateStandaloneGatewayConfig(writeStandaloneGatewayCheckConfig(t, unknown), dataDir, ""); err == nil || !strings.Contains(err.Error(), "not_a_setting") {
		t.Fatalf("another unknown key = %v, want it refused by name", err)
	}
	if _, err := loadConfigV8FileWithCredentials(writeStandaloneGatewayCheckConfig(t, withKey), dataDir, ""); err == nil {
		t.Fatal("the per-user v8 load accepted update_check; it keeps refusing the key with the migrate hint")
	}
}
