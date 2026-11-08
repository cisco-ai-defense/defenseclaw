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
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/legacyconnector"
)

// adminCascadeHooks is an administrator hooks file DefenseClaw never owns.
const adminCascadeHooks = "{\n  \"hooks\": {\n    \"pre_run_command\": [\n      {\n        \"command\": \"/usr/local/bin/audit\"\n      }\n    ]\n  }\n}\n"

// earlierCascadeEvents are the events releases 1.0.5 to 1.0.8 published the
// refusal on.
var earlierCascadeEvents = []string{"pre_user_prompt", "pre_read_code", "pre_write_code", "pre_run_command", "pre_mcp_tool_use"}

// earlierReleaseCascadeFile is current with the refusal an earlier release
// added to every event, after the entries already there.
func earlierReleaseCascadeFile(t *testing.T, opts Options, path string, current string) string {
	t.Helper()
	if current == "" {
		current = "{}"
	}
	doc, err := decodeOrderedObject([]byte(current))
	if err != nil {
		t.Fatal(err)
	}
	hooks := devinCascadeHooks(doc)
	if hooks == nil {
		hooks = newObject()
	}
	field, script := devinCascadeScript(opts)
	for _, event := range earlierCascadeEvents {
		existing, _ := hooks.get(event)
		list, _ := existing.([]any)
		entry := newObject()
		entry.set(field, script)
		entry.set("show_output", true)
		entry.set("working_directory", dirFor(opts, path))
		hooks.set(event, append(list, entry))
	}
	doc.set("hooks", hooks)
	rendered, err := encodeOrdered(doc)
	if err != nil {
		t.Fatal(err)
	}
	return string(rendered)
}

func devinCascadeStateOf(t *testing.T, states []State) State {
	t.Helper()
	for _, state := range states {
		if state.Connector == ConnectorDevinCascade {
			return state
		}
	}
	t.Fatalf("no %s state in %+v", ConnectorDevinCascade, states)
	return State{}
}

// Whatever hooks files exist, DefenseClaw writes none of them: the
// pre-rename file is imported as Devin Local hooks by current Devin clients
// (a refusal there blocks them), and no evidence shows that a build running
// Cascade pre-events reads the Devin file. The report must not call the
// state covered, and an administrator's files stay byte for byte.
func TestDevinCascadePublishesNothingAndClaimsNoCoverage(t *testing.T) {
	layouts := []struct {
		name          string
		devin, legacy string
	}{
		{name: "no hooks file"},
		{"pre-rename file only", "", adminCascadeHooks},
		{"Devin file only", adminCascadeHooks, ""},
		{"both files", adminCascadeHooks, adminCascadeHooks},
	}
	for _, layout := range layouts {
		t.Run(layout.name, func(t *testing.T) {
			opts := publishTestOptions(t)
			devinPath, _ := DevinSystemHooksPath(opts)
			legacyPath, _ := devinCascadeLegacyHooksPath(opts)
			files := map[string]string{devinPath: layout.devin, legacyPath: layout.legacy}
			for path, content := range files {
				if content != "" {
					writeFile(t, path, content)
				}
			}
			result, err := Publish(opts, []string{"devin"})
			if err != nil {
				t.Fatal(err)
			}
			state := devinCascadeStateOf(t, result.States)
			if state.Covered || state.Route != RouteUnsupported || state.OwnedEntries != 0 || len(state.Conflicts) != 0 {
				t.Fatalf("state = %+v", state)
			}
			if !strings.Contains(strings.Join(state.Details, "\n"), "not covered") {
				t.Fatalf("the coverage limit is not reported: %v", state.Details)
			}
			if !result.Complete() || len(result.MachinePolicyConnectors) != 0 {
				t.Fatalf("a connector that publishes nothing changed the result: %+v", result)
			}
			for path, content := range files {
				data, err := os.ReadFile(path)
				switch {
				case content == "" && !os.IsNotExist(err):
					t.Fatalf("created %s: %q, %v", path, data, err)
				case content != "" && string(data) != content:
					t.Fatalf("%s changed: %s", path, data)
				}
			}
			verify, err := VerifyAll(opts, []string{"devin"})
			if err != nil {
				t.Fatal(err)
			}
			if state := devinCascadeStateOf(t, verify.States); state.Covered || state.Route != RouteUnsupported || len(state.Conflicts) != 0 {
				t.Fatalf("verify state = %+v", state)
			}
			if _, err := RemoveAll(opts); err != nil {
				t.Fatal(err)
			}
			for path, content := range files {
				if data, _ := os.ReadFile(path); content != "" && string(data) != content {
					t.Fatalf("uninstall changed %s: %s", path, data)
				}
			}
		})
	}
}

// Releases 1.0.5 to 1.0.8 wrote the refusal into the Devin file, or into the
// pre-rename file when it existed. A publish withdraws it from both, so the
// Devin CLI that imports the pre-rename file is not refused, keeps the
// administrator entries, and removes a file only the refusal was left in.
func TestDevinCascadeWithdrawsTheRefusalAnEarlierReleaseWrote(t *testing.T) {
	cases := []struct {
		name                        string
		devinAdmin, legacyAdmin     string
		devinEarlier, legacyEarlier bool
	}{
		{"pre-rename file with administrator hooks", "", adminCascadeHooks, false, true},
		{"Devin file with administrator hooks", adminCascadeHooks, "", true, false},
		{"both files with administrator hooks", adminCascadeHooks, adminCascadeHooks, true, true},
		{"refusal alone in the Devin file", "", "", true, false},
		{"refusal alone in the pre-rename file", "", "", false, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			opts := publishTestOptions(t)
			devinPath, _ := DevinSystemHooksPath(opts)
			legacyPath, _ := devinCascadeLegacyHooksPath(opts)
			write := func(path, admin string, earlier bool) {
				switch {
				case earlier:
					writeFile(t, path, earlierReleaseCascadeFile(t, opts, path, admin))
				case admin != "":
					writeFile(t, path, admin)
				}
			}
			write(devinPath, c.devinAdmin, c.devinEarlier)
			write(legacyPath, c.legacyAdmin, c.legacyEarlier)

			verify, err := VerifyAll(opts, []string{"devin"})
			if err != nil {
				t.Fatal(err)
			}
			state := devinCascadeStateOf(t, verify.States)
			if len(state.Conflicts) == 0 || verify.Complete() {
				t.Fatalf("verify did not flag the refusal left by an earlier release: %+v", state)
			}
			leftIn := legacyPath
			if c.devinEarlier && !c.legacyEarlier {
				leftIn = devinPath
			}
			if !strings.Contains(strings.Join(state.Conflicts, " "), leftIn) {
				t.Fatalf("conflicts do not name %s: %v", leftIn, state.Conflicts)
			}

			result, err := Publish(opts, []string{"devin"})
			if err != nil {
				t.Fatal(err)
			}
			if state := devinCascadeStateOf(t, result.States); !state.Changed || len(state.Conflicts) != 0 || state.OwnedEntries != 0 {
				t.Fatalf("publish state = %+v", state)
			}
			for path, admin := range map[string]string{devinPath: c.devinAdmin, legacyPath: c.legacyAdmin} {
				data, err := os.ReadFile(path)
				if admin == "" {
					if !os.IsNotExist(err) {
						t.Fatalf("%s left behind: %q, %v", path, data, err)
					}
					continue
				}
				if string(data) != admin {
					t.Fatalf("%s after publish = %s", path, data)
				}
			}
		})
	}
}

// With ownership: verify_only the files belong to the administrator's policy
// tool: DefenseClaw reports the refusal an earlier release left and does not
// edit.
func TestDevinCascadeVerifyOnlyReportsButDoesNotEditAnEarlierRefusal(t *testing.T) {
	opts := publishTestOptions(t)
	opts = withPolicy(opts, ConnectorDevinCascade, func(p *config.EnterpriseConnectorPolicy) { p.Ownership = config.MachinePolicyOwnershipVerifyOnly })
	legacyPath, _ := devinCascadeLegacyHooksPath(opts)
	earlier := earlierReleaseCascadeFile(t, opts, legacyPath, adminCascadeHooks)
	writeFile(t, legacyPath, earlier)
	result, err := Publish(opts, []string{"devin"})
	if err != nil {
		t.Fatal(err)
	}
	state := devinCascadeStateOf(t, result.States)
	if len(state.Conflicts) == 0 || result.Complete() {
		t.Fatalf("state = %+v", state)
	}
	if strings.Contains(strings.Join(state.Details, " "), "missing_defenseclaw_hooks") {
		t.Fatalf("verify_only asks for an export that renders nothing: %v", state.Details)
	}
	if data, _ := os.ReadFile(legacyPath); string(data) != earlier {
		t.Fatalf("verify_only edited the file: %s", data)
	}
}

// An entry that only resembles the refusal, or any other administrator hook,
// is never withdrawn.
func TestDevinCascadeKeepsEntriesThatAreNotTheEarlierRefusal(t *testing.T) {
	opts := publishTestOptions(t)
	legacyPath, _ := devinCascadeLegacyHooksPath(opts)
	lookalike := "{\n  \"hooks\": {\n    \"pre_user_prompt\": [\n      {\n        \"command\": \"printf '%s\\\\n' 'Cascade is off' >&2; exit 2\"\n      }\n    ]\n  }\n}\n"
	writeFile(t, legacyPath, lookalike)
	result, err := Publish(opts, []string{"devin"})
	if err != nil {
		t.Fatal(err)
	}
	if state := devinCascadeStateOf(t, result.States); state.Changed || len(state.Conflicts) != 0 {
		t.Fatalf("state = %+v", state)
	}
	if data, _ := os.ReadFile(legacyPath); string(data) != lookalike {
		t.Fatalf("an administrator hook changed: %s", data)
	}
}

func TestDevinCascadeExportHasNothingToRender(t *testing.T) {
	_, err := Export(publishTestOptions(t), ConnectorDevinCascade, "json")
	if !errors.Is(err, ErrUnsupported) {
		t.Fatalf("export error = %v, want ErrUnsupported", err)
	}
}

// Which file each client reads is part of the contract, on every OS: the
// paths DefenseClaw withdraws from are the Devin file and the pre-rename one.
func TestDevinCascadePathsPinTheDevinHooksFile(t *testing.T) {
	cases := []struct {
		goos, devin, legacy string
	}{
		{"linux", "/etc/devin/hooks.json", "/etc/" + legacyconnector.CascadeMachineFolderUnix + "/hooks.json"},
		{"darwin", "/Library/Application Support/Devin/hooks.json", "/Library/Application Support/" + legacyconnector.CascadeMachineFolder + "/hooks.json"},
		{"windows", `C:\ProgramData\Devin\hooks.json`, `C:\ProgramData\` + legacyconnector.CascadeMachineFolder + `\hooks.json`},
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
