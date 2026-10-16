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

package connector

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"
)

// GAP-0564 (fix-up): after a loss DefenseClaw could not undo (settings_lost)
// the file recreated with its hooks only became the last known good copy, so
// a second loss before the account entered its settings again was put back
// "with that user's settings" (restored_last_good) and the settings_lost
// warning was gone for good.
func TestHermesSettingsLostSurvivesASecondLoss(t *testing.T) {
	conn, opts, configPath := hermesRestoreFixture(t, "")
	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, append([]byte(hermesAccountSettings), data...), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(hermesSpec.copyPath(opts.DataDir), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(configPath); err != nil {
		t.Fatal(err)
	}
	if err := conn.Setup(context.Background(), opts); err != nil {
		t.Fatalf("repair Setup: %v", err)
	}
	if status := AgentConfigStatus("hermes", opts, time.Time{}, true); status != AgentConfigSettingsLost {
		t.Fatalf("status after the first loss = %q", status)
	}

	if err := os.Remove(configPath); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	if err := conn.Setup(context.Background(), opts); err != nil {
		t.Fatalf("second repair Setup: %v", err)
	}
	if got := hermesTopKeys(t, configPath); got != "hooks" {
		t.Fatalf("config.yaml keys after the second loss = %s", got)
	}
	if status := AgentConfigStatus("hermes", opts, started, false); status != AgentConfigSettingsLost {
		t.Fatalf("the second repair reports %q, want %q", status, AgentConfigSettingsLost)
	}
	for pass := 0; pass < 2; pass++ {
		if status := AgentConfigStatus("hermes", opts, time.Time{}, true); status != AgentConfigSettingsLost {
			t.Fatalf("verify pass %d after the second loss = %q", pass, status)
		}
	}
}

// A file without the account's settings (emptied to DefenseClaw's hooks)
// that verifies does not replace a copy that has them: the next loss puts
// the settings back.
func TestHermesCopyWithSettingsIsNotReplacedByAHooksOnlyFile(t *testing.T) {
	conn, opts, configPath := hermesRestoreFixture(t, hermesAccountSettings)
	if copy, ok := hermesSpec.readCopy(opts.DataDir, configPath); !ok || !hermesSpec.hasSettings(copy.Bytes) {
		t.Fatalf("no copy with the account's settings after setup: %t", ok)
	}
	// The file is left with DefenseClaw's hooks only, and passes verify.
	hooksOnly, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	at := strings.Index(string(hooksOnly), "hooks:")
	if at < 0 {
		t.Fatalf("no hooks key in:\n%s", hooksOnly)
	}
	if err := os.WriteFile(configPath, hooksOnly[at:], 0o600); err != nil {
		t.Fatal(err)
	}
	if got := hermesTopKeys(t, configPath); got != "hooks" {
		t.Fatalf("hooks-only fixture keys = %s", got)
	}
	_ = AgentConfigStatus("hermes", opts, time.Time{}, true)
	if copy, ok := hermesSpec.readCopy(opts.DataDir, configPath); !ok || !hermesSpec.hasSettings(copy.Bytes) {
		t.Fatalf("a hooks-only file replaced the copy with the account's settings: %t", ok)
	}

	if err := os.Remove(configPath); err != nil {
		t.Fatal(err)
	}
	if err := conn.Setup(context.Background(), opts); err != nil {
		t.Fatalf("repair Setup: %v", err)
	}
	if got := hermesTopKeys(t, configPath); got != "bedrock,hooks,model" {
		t.Fatalf("restored config.yaml keys = %s, want the account's settings back", got)
	}
}

// The copy is bound to the file's path: with the managed backup record gone
// a missing file is still put back from it, not treated as a first setup.
func TestHermesSetupPutsBackTheCopyWhenTheBackupRecordIsGone(t *testing.T) {
	conn, opts, configPath := hermesRestoreFixture(t, hermesAccountSettings)
	if err := os.Remove(managedFileBackupPath(opts.DataDir, "hermes", "config.yaml")); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(configPath); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	if err := conn.Setup(context.Background(), opts); err != nil {
		t.Fatalf("repair Setup: %v", err)
	}
	if got := hermesTopKeys(t, configPath); got != "bedrock,hooks,model" {
		t.Fatalf("config.yaml keys = %s, want the account's settings from the copy", got)
	}
	if status := AgentConfigStatus("hermes", opts, started, false); status != AgentConfigRestoredLastGood {
		t.Fatalf("repair status = %q", status)
	}
	present, err := OwnedHooksPresent(conn, opts)
	if err != nil || !present {
		t.Fatalf("hooks after the repair: %t %v", present, err)
	}
}
