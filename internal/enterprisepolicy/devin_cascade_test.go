// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"os"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// The Cascade bridge rides on the devin connector: it goes into the Devin
// machine hooks file (created when no hooks file exists) or into the
// pre-rename one Devin Desktop falls back to, keeps administrator entries,
// never reaches the runtime descriptor, and is withdrawn byte-identically
// by ownership: off and by uninstall.
func TestDevinCascadeBridgeFollowsTheFileDevinDesktopReads(t *testing.T) {
	stateFor := func(t *testing.T, result Result) State {
		t.Helper()
		for _, state := range result.States {
			if state.Connector == ConnectorDevinCascade {
				return state
			}
		}
		t.Fatalf("no %s state in %+v", ConnectorDevinCascade, result.States)
		return State{}
	}
	message := devinCascadeMessage

	t.Run("no hooks file", func(t *testing.T) {
		opts := publishTestOptions(t)
		devinPath, _ := DevinSystemHooksPath(opts)
		result, err := Publish(opts, []string{"devin"})
		if err != nil {
			t.Fatal(err)
		}
		if state := stateFor(t, result); !state.Covered || state.OwnedEntries != len(devinCascadeEvents) {
			t.Fatalf("state = %+v", state)
		}
		if len(result.MachinePolicyConnectors) != 0 {
			t.Fatalf("the bridge reached the runtime descriptor: %v", result.MachinePolicyConnectors)
		}
		data, err := os.ReadFile(devinPath)
		if err != nil || strings.Count(string(data), message) != len(devinCascadeEvents) {
			t.Fatalf("Devin hooks file = %q, %v", data, err)
		}
		off := withPolicy(opts, ConnectorDevinCascade, func(p *config.EnterpriseConnectorPolicy) { p.Ownership = config.MachinePolicyOwnershipOff })
		if _, err := Publish(off, []string{"devin"}); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Lstat(devinPath); !os.IsNotExist(err) {
			t.Fatalf("ownership: off left the created hooks file: %v", err)
		}
	})

	t.Run("pre-rename file only", func(t *testing.T) {
		opts := publishTestOptions(t)
		devinPath, _ := DevinSystemHooksPath(opts)
		legacyPath, _ := devinCascadeLegacyHooksPath(opts)
		admin := "{\n  \"hooks\": {\n    \"pre_run_command\": [\n      {\n        \"command\": \"/usr/local/bin/audit\"\n      }\n    ]\n  }\n}\n"
		writeFile(t, legacyPath, admin)
		result, err := Publish(opts, []string{"devin"})
		if err != nil {
			t.Fatal(err)
		}
		if state := stateFor(t, result); !state.Covered || state.ForeignEntries != 1 {
			t.Fatalf("state = %+v", state)
		}
		data, _ := os.ReadFile(legacyPath)
		if !strings.Contains(string(data), "/usr/local/bin/audit") || strings.Count(string(data), message) != len(devinCascadeEvents) {
			t.Fatalf("pre-rename hooks file = %s", data)
		}
		if _, err := os.Lstat(devinPath); !os.IsNotExist(err) {
			t.Fatalf("created the Devin hooks file, which would hide the administrator's pre-rename one: %v", err)
		}
		if _, err := RemoveAll(opts); err != nil {
			t.Fatal(err)
		}
		if data, _ := os.ReadFile(legacyPath); string(data) != admin {
			t.Fatalf("uninstall left %s", data)
		}
	})
}
