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
