// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"path/filepath"
	"testing"
)

// GAP-0376: a notify entry that runs DefenseClaw's own hook launcher with
// arguments after "notify" was left by teardown (argv had to be exactly two
// items), so an uninstall left Codex calling a removed program. A user's own
// notifier stays.
func TestCodexTeardownRemovesADefenseClawNotifyWithExtraArguments(t *testing.T) {
	home := t.TempDir()
	restore, err := BindUserHomeDir(home)
	if err != nil {
		t.Fatal(err)
	}
	defer restore()
	launcher := filepath.Join(home, ".local", "bin", windowsHookBinaryName)
	cfg := map[string]interface{}{
		"notify": []interface{}{launcher, "notify", "--connector", "codex"},
		"model":  "keep",
	}
	if !codexNotifyLooksManaged(cfg["notify"], SetupOpts{}) {
		t.Fatal("DefenseClaw's launcher with extra notify arguments is not recognized")
	}
	if err := restoreCodexNotify(cfg, codexConfigBackup{}, SetupOpts{}); err != nil {
		t.Fatal(err)
	}
	if _, kept := cfg["notify"]; kept || cfg["model"] != "keep" {
		t.Fatalf("after restore: %v", cfg)
	}
	for _, own := range [][]interface{}{
		{"/usr/bin/notify-send", "notify", "--connector", "codex"},
		{"python3", "notify", "x"},
	} {
		if codexNotifyLooksManaged(own, SetupOpts{}) {
			t.Fatalf("a user's own notifier %v is claimed", own)
		}
	}
}
