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

// adminCascadeHooks is an administrator hooks file DefenseClaw never owns.
const adminCascadeHooks = "{\n  \"hooks\": {\n    \"pre_run_command\": [\n      {\n        \"command\": \"/usr/local/bin/audit\"\n      }\n    ]\n  }\n}\n"

// The Cascade bridge rides on the devin connector: it goes into the Devin
// machine hooks file (created when no hooks file exists), never into the
// pre-rename one the Devin CLI imports as Devin Local hooks, keeps
// administrator entries, never reaches the runtime descriptor, and is
// withdrawn byte-identically by ownership: off and by uninstall.
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
		writeFile(t, legacyPath, adminCascadeHooks)
		result, err := Publish(opts, []string{"devin"})
		if err != nil {
			t.Fatal(err)
		}
		if state := stateFor(t, result); state.Route != RouteUnsupported || state.OwnedEntries != 0 || len(state.Conflicts) != 0 {
			t.Fatalf("state = %+v", state)
		}
		if !result.Complete() {
			t.Fatalf("an administrator pre-rename file alone made the publication incomplete: %+v", result.States)
		}
		// The Devin CLI and the Desktop engine import this file as Devin Local
		// hooks, so a refusal in it would block current Devin.
		if data, _ := os.ReadFile(legacyPath); string(data) != adminCascadeHooks {
			t.Fatalf("pre-rename hooks file changed: %s", data)
		}
		if _, err := os.Lstat(devinPath); !os.IsNotExist(err) {
			t.Fatalf("created the Devin hooks file, which would hide the administrator's pre-rename one: %v", err)
		}
		if _, err := RemoveAll(opts); err != nil {
			t.Fatal(err)
		}
		if data, _ := os.ReadFile(legacyPath); string(data) != adminCascadeHooks {
			t.Fatalf("uninstall left %s", data)
		}
	})

	t.Run("both files", func(t *testing.T) {
		opts := publishTestOptions(t)
		devinPath, _ := DevinSystemHooksPath(opts)
		legacyPath, _ := devinCascadeLegacyHooksPath(opts)
		writeFile(t, devinPath, adminCascadeHooks)
		writeFile(t, legacyPath, adminCascadeHooks)
		result, err := Publish(opts, []string{"devin"})
		if err != nil {
			t.Fatal(err)
		}
		if state := stateFor(t, result); !state.Covered || state.ForeignEntries != 1 || state.OwnedEntries != len(devinCascadeEvents) {
			t.Fatalf("state = %+v", state)
		}
		if data, _ := os.ReadFile(devinPath); strings.Count(string(data), message) != len(devinCascadeEvents) || !strings.Contains(string(data), "/usr/local/bin/audit") {
			t.Fatalf("Devin hooks file = %s", data)
		}
		if data, _ := os.ReadFile(legacyPath); string(data) != adminCascadeHooks {
			t.Fatalf("pre-rename hooks file changed: %s", data)
		}
		if _, err := RemoveAll(opts); err != nil {
			t.Fatal(err)
		}
		for _, path := range []string{devinPath, legacyPath} {
			if data, _ := os.ReadFile(path); string(data) != adminCascadeHooks {
				t.Fatalf("uninstall left %s: %s", path, data)
			}
		}
	})
}

// Releases 1.0.5 to 1.0.8 put the refusal into the pre-rename file too. A
// publish withdraws it, so the Devin CLI that imports that file is not
// refused, and keeps the administrator entries byte for byte.
func TestDevinCascadeWithdrawsTheRefusalAnEarlierReleaseWroteIntoThePreRenameFile(t *testing.T) {
	for _, withDevinFile := range []bool{false, true} {
		opts := publishTestOptions(t)
		devinPath, _ := DevinSystemHooksPath(opts)
		legacyPath, _ := devinCascadeLegacyHooksPath(opts)
		earlier, _, err := mergeDevinCascadeHooks(opts, legacyPath, []byte(adminCascadeHooks))
		if err != nil {
			t.Fatal(err)
		}
		writeFile(t, legacyPath, string(earlier))
		if withDevinFile {
			writeFile(t, devinPath, adminCascadeHooks)
		}

		verify, err := VerifyAll(opts, []string{"devin"})
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, state := range verify.States {
			if state.Connector == ConnectorDevinCascade {
				found = len(state.Conflicts) > 0 && strings.Contains(strings.Join(state.Conflicts, " "), legacyPath)
			}
		}
		if !found {
			t.Fatalf("withDevinFile=%v: verify did not flag the refusal left in the pre-rename file: %+v", withDevinFile, verify.States)
		}

		if _, err := Publish(opts, []string{"devin"}); err != nil {
			t.Fatal(err)
		}
		if data, _ := os.ReadFile(legacyPath); string(data) != adminCascadeHooks {
			t.Fatalf("withDevinFile=%v: pre-rename file after publish = %s", withDevinFile, data)
		}
		data, _ := os.ReadFile(devinPath)
		if got := strings.Count(string(data), devinCascadeMessage); got != len(devinCascadeEvents)*boolInt(withDevinFile) {
			t.Fatalf("withDevinFile=%v: Devin hooks file carries %d refusals: %s", withDevinFile, got, data)
		}
	}
}

func boolInt(v bool) int {
	if v {
		return 1
	}
	return 0
}

// Which file each client reads is part of the contract: the refusal is
// published only into the Devin hooks file, on every OS.
func TestDevinCascadePathsPinTheDevinHooksFile(t *testing.T) {
	cases := []struct {
		goos, devin, legacy string
	}{
		{"linux", "/etc/devin/hooks.json", "/etc/windsurf/hooks.json"},
		{"darwin", "/Library/Application Support/Devin/hooks.json", "/Library/Application Support/Windsurf/hooks.json"},
		{"windows", `C:\ProgramData\Devin\hooks.json`, `C:\ProgramData\Windsurf\hooks.json`},
	}
	for _, c := range cases {
		opts := Options{GOOS: c.goos, WindowsProgramData: `C:\ProgramData`}
		devin, err := DevinSystemHooksPath(opts)
		if err != nil || devin != c.devin {
			t.Errorf("%s: Devin path = %q, %v; want %q", c.goos, devin, err, c.devin)
		}
		legacy, err := devinCascadeLegacyHooksPath(opts)
		if err != nil || legacy != c.legacy {
			t.Errorf("%s: pre-rename path = %q, %v; want %q", c.goos, legacy, err, c.legacy)
		}
	}
}
