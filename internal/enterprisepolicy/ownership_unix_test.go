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

package enterprisepolicy

import (
	"os"
	"strings"
	"testing"
)

// Every user's agent reads machine policy, so a policy file DefenseClaw
// published is 0644. An administrator who tightens one (0600 on
// /etc/codex/requirements.toml makes every standard user's Codex refuse to
// start) fails verify, which does not report the connector in place, so the
// lifecycle's ensure re-applies; the next publish restores the mode.
func TestVerifyRequiresThePublishedModeOfOwnedPolicyFiles(t *testing.T) {
	withHigherSources(t)
	connectors := []string{"claudecode", "codex", "copilot", "cursor"}
	for _, name := range connectors {
		t.Run(name, func(t *testing.T) {
			opts := publishTestOptions(t)
			if _, err := Publish(opts, connectors); err != nil {
				t.Fatal(err)
			}
			var files []string
			for _, recordName := range []string{name, claudeVersionFloorRecord} {
				if recordName == claudeVersionFloorRecord && name != "claudecode" {
					continue
				}
				record, err := loadRecord(opts, recordName)
				if err != nil || record == nil {
					t.Fatalf("%s record: %v %v", recordName, record, err)
				}
				files = append(files, record.Path)
			}
			for _, file := range files {
				if err := os.Chmod(file, 0o600); err != nil {
					t.Fatal(err)
				}
			}

			verify, err := VerifyAll(opts, connectors)
			if err != nil {
				t.Fatal(err)
			}
			if containsString(verify.MachinePolicyConnectors, name) {
				t.Fatalf("a connector whose policy file agents cannot read is not in place: %v", verify.MachinePolicyConnectors)
			}
			for _, state := range verify.States {
				if state.Connector != name {
					continue
				}
				if state.Covered || !hasConflict(state, "mode 0600") || !hasConflict(state, files[0]) {
					t.Fatalf("verify must name the file and its mode: covered=%v %v", state.Covered, state.Conflicts)
				}
			}

			if _, err := Publish(opts, connectors); err != nil {
				t.Fatal(err)
			}
			for _, file := range files {
				info, err := os.Stat(file)
				if err != nil || info.Mode().Perm() != 0o644 {
					t.Fatalf("the next publish must restore %s to 0644: %v %v", file, info.Mode(), err)
				}
			}
			verify, err = VerifyAll(opts, connectors)
			if err != nil || !containsString(verify.MachinePolicyConnectors, name) {
				t.Fatalf("after the repair the connector is in place: %v %v", verify.MachinePolicyConnectors, err)
			}
			for _, state := range verify.States {
				if state.Connector == name && (!state.Covered || strings.Contains(strings.Join(state.Conflicts, "\n"), "mode 0")) {
					t.Fatalf("after the repair verify passes: %v", state.Conflicts)
				}
			}
		})
	}
}
