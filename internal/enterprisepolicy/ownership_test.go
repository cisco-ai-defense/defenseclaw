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
	"runtime"
	"strings"
	"testing"
)

func cursorHooksPath(t *testing.T, opts Options) string {
	t.Helper()
	path, err := CursorEnterpriseHooksPath(opts)
	if err != nil {
		t.Fatal(err)
	}
	return path
}

func claudeDropIn(t *testing.T, opts Options) string {
	t.Helper()
	path, err := claudeDropInPath(opts)
	if err != nil {
		t.Fatal(err)
	}
	return path
}

func copilotDropIn(t *testing.T, opts Options) string {
	t.Helper()
	path, err := copilotDropInPath(opts)
	if err != nil {
		t.Fatal(err)
	}
	return path
}

func mustNotExist(t *testing.T, path, why string) {
	t.Helper()
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("%s: %s must not exist (err=%v)", why, path, err)
	}
}

func mustReconcile(t *testing.T, target Target, opts Options) State {
	t.Helper()
	state, err := target.Reconcile(opts)
	if err != nil {
		t.Fatal(err)
	}
	return state
}

func mustRemove(t *testing.T, target Target, opts Options) State {
	t.Helper()
	state, err := target.RemoveOwned(opts)
	if err != nil {
		t.Fatal(err)
	}
	return state
}

// A reconcile after an administrator edit folds the edit into the file
// DefenseClaw writes. Removal must keep the edit instead of restoring the
// install-time preimage.
func TestRemoveAfterReconcileKeepsLaterAdministratorEdits(t *testing.T) {
	t.Run("codex", func(t *testing.T) {
		opts := testOptions(t)
		path := codexPath(t, opts)
		writeFile(t, path, adminCodexRequirements)
		mustReconcile(t, codexTarget{}, opts)
		writeFile(t, path, readFile(t, path)+"\n[[hooks.Stop]]\n\n[[hooks.Stop.hooks]]\ntype = \"command\"\ncommand = \"/usr/local/bin/admin-stop\"\n")
		mustReconcile(t, codexTarget{}, opts)
		mustRemove(t, codexTarget{}, opts)
		got := readFile(t, path)
		if !strings.Contains(got, "/usr/local/bin/admin-stop") || !strings.Contains(got, "/usr/local/bin/company-audit") {
			t.Fatalf("removal dropped administrator content added after install:\n%s", got)
		}
		if strings.Contains(got, "defenseclaw") || strings.Contains(got, "allow_managed_hooks_only") {
			t.Fatalf("removal left DefenseClaw content:\n%s", got)
		}
	})
	t.Run("cursor", func(t *testing.T) {
		opts := testOptions(t)
		path := cursorHooksPath(t, opts)
		writeFile(t, path, adminCursorHooks)
		mustReconcile(t, cursorTarget{}, opts)
		edited := strings.Replace(readFile(t, path), `"command": "/usr/local/bin/company-format"`, `"command": "/usr/local/bin/company-format"
      },
      {
        "command": "/usr/local/bin/admin-new"`, 1)
		if !strings.Contains(edited, "admin-new") {
			t.Fatal("test edit did not apply")
		}
		writeFile(t, path, edited)
		mustReconcile(t, cursorTarget{}, opts)
		mustRemove(t, cursorTarget{}, opts)
		got := readFile(t, path)
		if !strings.Contains(got, "/usr/local/bin/admin-new") || !strings.Contains(got, "company-shell-policy") || strings.Contains(got, testHookBinary) {
			t.Fatalf("removal must keep the admin hook added after install and drop only DefenseClaw's:\n%s", got)
		}
	})
	t.Run("codex deletion is not resurrected", func(t *testing.T) {
		opts := testOptions(t)
		path := codexPath(t, opts)
		writeFile(t, path, adminCodexRequirements)
		mustReconcile(t, codexTarget{}, opts)
		writeFile(t, path, strings.Replace(readFile(t, path), "allowed_approval_policies = [\"on-request\"] # keep approvals on\n", "", 1))
		mustReconcile(t, codexTarget{}, opts)
		mustRemove(t, codexTarget{}, opts)
		if got := readFile(t, path); strings.Contains(got, "allowed_approval_policies") {
			t.Fatalf("removal restored a setting the administrator deleted after install:\n%s", got)
		}
	})
	t.Run("opencode", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("the unix plugin path is not absolute on Windows")
		}
		opts := testOptions(t)
		installTestOpenCodePlugin(t, &opts)
		path, _ := OpenCodeManagedConfigPath(opts)
		writeFile(t, path, "{\n  \"plugin\": [\"company-audit\"]\n}\n")
		mustReconcile(t, opencodeTarget{}, opts)
		writeFile(t, path, strings.Replace(readFile(t, path), `"company-audit",`, `"company-audit", "admin-later",`, 1))
		if !strings.Contains(readFile(t, path), "admin-later") {
			t.Fatal("test edit did not apply")
		}
		mustReconcile(t, opencodeTarget{}, opts)
		mustRemove(t, opencodeTarget{}, opts)
		if got := readFile(t, path); !strings.Contains(got, "admin-later") || strings.Contains(got, opts.OpenCodePluginPath) {
			t.Fatalf("removal must keep the admin plugin added after install:\n%s", got)
		}
	})
}

// A file that already held DefenseClaw's content (an admin-deployed export,
// or one left by a crash before the record was saved) must not be recorded
// as the administrator's preimage, or removal would put DefenseClaw's hooks
// and lock back for every user.
func TestPreimageNeverKeepsDefenseClawContent(t *testing.T) {
	t.Run("codex export deployed then merge", func(t *testing.T) {
		opts := testOptions(t)
		path := codexPath(t, opts)
		exported, err := codexTarget{}.Export(opts, "toml")
		if err != nil {
			t.Fatal(err)
		}
		writeFile(t, path, string(exported))
		mustReconcile(t, codexTarget{}, opts)
		mustRemove(t, codexTarget{}, opts)
		mustNotExist(t, path, "a requirements file that held only DefenseClaw content")
	})
	t.Run("codex admin content plus export", func(t *testing.T) {
		opts := testOptions(t)
		path := codexPath(t, opts)
		writeFile(t, path, adminCodexRequirements)
		// The export is the complete document: the admin file with
		// DefenseClaw's blocks merged in.
		exported, err := codexTarget{}.Export(opts, "toml")
		if err != nil {
			t.Fatal(err)
		}
		writeFile(t, path, string(exported))
		mustReconcile(t, codexTarget{}, opts)
		mustRemove(t, codexTarget{}, opts)
		if got := readFile(t, path); got != adminCodexRequirements {
			t.Fatalf("removal must leave only the administrator text:\n%s", got)
		}
	})
	t.Run("claude drop-in deployed from export", func(t *testing.T) {
		withHigherSources(t)
		opts := testOptions(t)
		exported, err := claudeTarget{}.Export(opts, "json")
		if err != nil {
			t.Fatal(err)
		}
		path := claudeDropIn(t, opts)
		writeFile(t, path, strings.Replace(string(exported), "\n", "\n\n", 1))
		mustReconcile(t, claudeTarget{}, opts)
		mustRemove(t, claudeTarget{}, opts)
		mustNotExist(t, path, "a drop-in that held only DefenseClaw content")
	})
	t.Run("record from an older release", func(t *testing.T) {
		opts := testOptions(t)
		path := codexPath(t, opts)
		mustReconcile(t, codexTarget{}, opts)
		current := []byte(readFile(t, path))
		legacy := &ownershipRecord{Connector: codexConnector, Path: path, PreimageExisted: true, Preimage: current, PreimageSHA256: sha256Hex(current), PostimageSHA256: sha256Hex(current)}
		if err := saveRecord(opts, legacy); err != nil {
			t.Fatal(err)
		}
		mustRemove(t, codexTarget{}, opts)
		mustNotExist(t, path, "a legacy preimage that held only DefenseClaw content")
	})
}

// Whole-file drop-ins: removal never leaves an empty file, which is not
// valid JSON.
func TestRemoveNeverLeavesAnEmptyDropIn(t *testing.T) {
	for _, tc := range []struct {
		name   string
		target Target
		path   func(*testing.T, Options) string
	}{
		{"claudecode", claudeTarget{}, claudeDropIn},
		{"copilot", copilotTarget{}, copilotDropIn},
	} {
		t.Run(tc.name, func(t *testing.T) {
			withHigherSources(t)
			opts := testOptions(t)
			path := tc.path(t, opts)
			exported, err := tc.target.Export(opts, "json")
			if err != nil {
				t.Fatal(err)
			}
			// The drop-in pre-existed (admin-deployed export) and was later
			// re-deployed with different bytes by the MDM.
			writeFile(t, path, string(exported))
			mustReconcile(t, tc.target, opts)
			writeFile(t, path, strings.TrimSpace(string(exported)))
			mustRemove(t, tc.target, opts)
			if info, err := os.Stat(path); err == nil && info.Size() == 0 {
				t.Fatalf("removal left a zero-byte drop-in at %s", path)
			}
			mustNotExist(t, path, "a changed drop-in that holds only DefenseClaw content")

			// An administrator's own content under the drop-in name that
			// DefenseClaw replaced is restored, never truncated.
			fresh := testOptions(t)
			own := "{\"env\": {\"COMPANY\": \"1\"}}\n"
			writeFile(t, tc.path(t, fresh), own)
			mustReconcile(t, tc.target, fresh)
			mustRemove(t, tc.target, fresh)
			if got := readFile(t, tc.path(t, fresh)); got != own {
				t.Fatalf("removal must restore the administrator drop-in, got %q", got)
			}
		})
	}
}

// Uninstall on a host where DefenseClaw never published a target must
// leave the administrator's files byte-identical.
func TestRemoveAllLeavesUntouchedFilesByteIdentical(t *testing.T) {
	withHigherSources(t)
	opts := testOptions(t)
	cursor := "{\"version\":1,\"hooks\":{\"beforeShellExecution\":[{\"command\":\"cd /srv && /usr/local/bin/check\"}]}}"
	codex := "allowed_approval_policies = [\"on-request\"]"
	writeFile(t, cursorHooksPath(t, opts), cursor)
	writeFile(t, codexPath(t, opts), codex)
	claudeExport, err := claudeTarget{}.Export(opts, "json")
	if err != nil {
		t.Fatal(err)
	}
	copilotExport, err := copilotTarget{}.Export(opts, "json")
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, claudeDropIn(t, opts), string(claudeExport))
	writeFile(t, copilotDropIn(t, opts), string(copilotExport))
	if _, err := RemoveAll(opts); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, cursorHooksPath(t, opts)); got != cursor {
		t.Fatalf("cursor hooks.json was rewritten:\n%s", got)
	}
	if got := readFile(t, codexPath(t, opts)); got != codex {
		t.Fatalf("requirements.toml was rewritten: %q", got)
	}
	if got := readFile(t, claudeDropIn(t, opts)); got != string(claudeExport) {
		t.Fatal("an administrator-deployed Claude drop-in without a DefenseClaw record must stay")
	}
	if got := readFile(t, copilotDropIn(t, opts)); got != string(copilotExport) {
		t.Fatal("an administrator-deployed Copilot drop-in without a DefenseClaw record must stay")
	}
}
