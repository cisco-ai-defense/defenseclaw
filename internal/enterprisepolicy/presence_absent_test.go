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
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// MachinePolicyPresent recognizes only the current registration exactly, so a
// registered hook whose timeout or arguments changed is not present to it
// although the vendor still runs the command. MachinePolicyAbsent must not
// call such a hook absent: it says absent only when the files were read and
// name no DefenseClaw hook at all.
func TestMachinePolicyAbsentIsNotTheNegationOfPresent(t *testing.T) {
	timeoutField := regexp.MustCompile(`timeout = (\d+)`)
	for _, tc := range []struct {
		connector string
		path      func(Options) (string, error)
		drift     func(string) string
	}{
		{"codex", CodexRequirementsPath, func(text string) string {
			return timeoutField.ReplaceAllStringFunc(text, func(field string) string {
				n, _ := strconv.Atoi(strings.TrimPrefix(field, "timeout = "))
				return "timeout = " + strconv.Itoa(n+1)
			})
		}},
		{"claudecode", func(opts Options) (string, error) {
			dir, err := ClaudeManagedDir(opts)
			return filepath.Join(dir, "managed-settings.d", DefenseClawDropInName), err
		}, func(text string) string {
			return strings.ReplaceAll(text, "\"--enterprise-managed\"", "\"--enterprise-managed\", \"--changed\"")
		}},
		{"cursor", CursorEnterpriseHooksPath, func(text string) string {
			return strings.ReplaceAll(text, "--enterprise-managed", "--enterprise-managed --changed")
		}},
		{"copilot", copilotDropInPath, func(text string) string {
			return strings.ReplaceAll(text, "--enterprise-managed --event ", "--enterprise-managed --changed --event ")
		}},
		{"opencode", OpenCodeManagedConfigPath, func(text string) string {
			return strings.ReplaceAll(text, path.Dir(testOpenCodePlugin), path.Dir(testOpenCodePlugin)+"-changed")
		}},
	} {
		t.Run(tc.connector, func(t *testing.T) {
			opts := publishTestOptions(t)
			installTestOpenCodePlugin(t, &opts)
			assertAbsent := func(step string, want bool) {
				t.Helper()
				if got, err := MachinePolicyAbsent(opts, tc.connector); err != nil || got != want {
					t.Fatalf("%s: absent=%v err=%v, want absent=%v", step, got, err, want)
				}
			}
			assertAbsent("nothing published", true)
			if _, err := Publish(opts, []string{tc.connector}); err != nil {
				t.Fatal(err)
			}
			assertAbsent("published", false)
			path, err := tc.path(opts)
			if err != nil {
				t.Fatal(err)
			}
			file := path
			if _, statErr := os.Stat(file); statErr != nil {
				t.Fatalf("published file: %v", statErr)
			}
			published := readFile(t, file)
			drifted := tc.drift(published)
			if drifted == published {
				t.Fatalf("the drift changed nothing in %s", file)
			}
			writeFile(t, file, drifted)
			assertAbsent("registration drifted", false)

			// Benign twin: an unrelated administrator policy that names no
			// DefenseClaw hook is read and holds none.
			writeFile(t, file, "# administrator policy\n")
			if tc.connector != "codex" {
				writeFile(t, file, "{\"permissions\": {\"allow\": [\"Read\"]}}\n")
			}
			assertAbsent("unrelated administrator policy", true)

			// A file that cannot be parsed or trusted proves nothing.
			if tc.connector == "codex" {
				writeFile(t, file, "[hooks\n")
				if got, err := MachinePolicyAbsent(opts, tc.connector); err == nil || got {
					t.Fatalf("an unparsable file must be an error, not absent: absent=%v err=%v", got, err)
				}
			}
		})
	}
}

// Copilot loads every effective JSON drop-in of policy.d, so a DefenseClaw hook
// in a sibling file is registered although MachinePolicyPresent, which reads
// the DefenseClaw drop-in alone, says false. Absence is proven only when every
// effective drop-in was read and parsed and none names DefenseClaw.
func TestMachinePolicyAbsentReadsEveryEffectiveCopilotDropIn(t *testing.T) {
	opts := publishTestOptions(t)
	if _, err := Publish(opts, []string{"copilot"}); err != nil {
		t.Fatal(err)
	}
	dir, err := CopilotPolicyDir(opts)
	if err != nil {
		t.Fatal(err)
	}
	owned, err := copilotDropInPath(opts)
	if err != nil {
		t.Fatal(err)
	}
	published := readFile(t, owned)
	if err := os.Remove(owned); err != nil {
		t.Fatal(err)
	}
	check := func(step string, wantAbsent, wantErr bool) {
		t.Helper()
		got, err := MachinePolicyAbsent(opts, "copilot")
		if (err != nil) != wantErr || got != wantAbsent {
			t.Fatalf("%s: absent=%v err=%v, want absent=%v error=%v", step, got, err, wantAbsent, wantErr)
		}
	}
	check("no drop-in", true, false)

	// The same hook under another effective name stays registered.
	writeFile(t, filepath.Join(dir, "91-policy.json"), published)
	check("hook in a sibling drop-in", false, false)
	// A drifted copy in a sibling is a registered hook as well.
	writeFile(t, filepath.Join(dir, "91-policy.json"), strings.ReplaceAll(published, "--enterprise-managed --event ", "--enterprise-managed --changed --event "))
	check("drifted hook in a sibling drop-in", false, false)

	// Files Copilot does not load are not policy.
	if err := os.Remove(filepath.Join(dir, "91-policy.json")); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(dir, ".91-draft.json"), published)
	writeFile(t, filepath.Join(dir, "91-policy.json.bak"), published)
	check("hidden and non-JSON copies", true, false)

	// Benign twin: unrelated administrator hooks name no DefenseClaw hook.
	writeFile(t, filepath.Join(dir, "50-admin.json"), "{\"hooks\": {\"preToolUse\": [{\"type\": \"command\", \"bash\": \"/usr/local/bin/audit-tool\"}]}}\n")
	check("unrelated administrator drop-in", true, false)

	// A source that cannot be parsed proves nothing.
	writeFile(t, filepath.Join(dir, "60-broken.json"), "{\"hooks\": ")
	check("unparsable sibling drop-in", false, true)
}
