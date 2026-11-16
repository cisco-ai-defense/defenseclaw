// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

// The teardown of a Hermes config.yaml the account edited after Setup removes
// only what Setup added. A hooks field Setup created goes as a whole, so the
// file is the copy Setup captured plus the account's edit, byte for byte, and
// an unedited file is that copy again; a hooks field of the account's own
// stays (GAP-0262).
func TestHermesTeardownPutsBackTheCapturedBytesAroundAnEdit(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows registers the native hook launcher, not a hook script")
	}
	const template = "# Hermes template\nmodel:\n  default: \"x\"   # quoted\n\n# trailing note\n"
	crlf := strings.ReplaceAll(template, "\n", "\r\n")
	appendText := func(text string) func(string) string {
		return func(current string) string { return current + text }
	}
	replace := func(old, new string) func(string) string {
		return func(current string) string { return strings.Replace(current, old, new, 1) }
	}
	cases := []struct {
		name     string
		pristine string
		edit     func(string) string
		want     string
	}{
		{"no hooks field, comment appended", template, appendText("# user edit\n"), template + "# user edit\n"},
		{"no hooks field, setting changed", template, replace(`"x"`, `"y"`), strings.Replace(template, `"x"`, `"y"`, 1)},
		{"no hooks field, unedited", template, nil, template},
		{"crlf, comment appended", crlf, appendText("# user edit\r\n"), crlf + "# user edit\r\n"},
		{"own empty hooks field", "a: 1\nhooks: {}\nb: 2\n", nil, "a: 1\nhooks: {}\nb: 2\n"},
		{"Hermes bootstrap", "{}\n", nil, "{}\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := testenv.PrivateTempDir(t)
			dataDir := filepath.Join(root, ".defenseclaw")
			script := filepath.Join(dataDir, "hooks", "hermes-hook.sh")
			path := filepath.Join(root, "hermes", "config.yaml")
			setupHermesConfigForTeardownTest(t, dataDir, path, script, tc.pristine)
			if tc.edit != nil {
				current := readHookFileForTest(t, path)
				if err := os.WriteFile(path, []byte(tc.edit(current)), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if err := NewHermesConnector().removeConfigEntriesWithManagedBackup(
				SetupOpts{DataDir: dataDir}, "config.yaml", path, script,
			); err != nil {
				t.Fatalf("remove hook entries: %v", err)
			}
			if got := readHookFileForTest(t, path); got != tc.want {
				t.Fatalf("config.yaml after teardown =\n%q\nwant\n%q", got, tc.want)
			}
		})
	}

	// A copy Setup captured after an earlier enrollment holds only
	// DefenseClaw's hooks (the file DefenseClaw wrote was put back): the
	// teardown removes them and the field they needed, which is the file
	// before the earlier enrollment.
	t.Run("captured copy holds only DefenseClaw hooks", func(t *testing.T) {
		root := testenv.PrivateTempDir(t)
		dataDir := filepath.Join(root, ".defenseclaw")
		script := filepath.Join(dataDir, "hooks", "hermes-hook.sh")
		path := filepath.Join(root, "hermes", "config.yaml")
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(template), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := patchHermesHooks(path, script, ""); err != nil {
			t.Fatal(err)
		}
		setupHermesConfigForTeardownTest(t, dataDir, path, script, readHookFileForTest(t, path))
		if !hermesConfigBackupHoldsOwnedHooks(dataDir, "config.yaml", path, script) {
			t.Fatal("fixture: the captured copy must hold DefenseClaw's hooks")
		}
		if err := NewHermesConnector().removeConfigEntriesWithManagedBackup(
			SetupOpts{DataDir: dataDir}, "config.yaml", path, script,
		); err != nil {
			t.Fatalf("remove hook entries: %v", err)
		}
		if got := readHookFileForTest(t, path); got != template {
			t.Fatalf("config.yaml after teardown =\n%q\nwant\n%q", got, template)
		}
	})

	// The account's own hook stays, and so does its hooks field.
	t.Run("own hook kept", func(t *testing.T) {
		root := testenv.PrivateTempDir(t)
		dataDir := filepath.Join(root, ".defenseclaw")
		script := filepath.Join(dataDir, "hooks", "hermes-hook.sh")
		path := filepath.Join(root, "hermes", "config.yaml")
		pristine := "a: 1\nhooks:\n  pre_tool_call:\n  - command: /usr/local/bin/mine\n"
		setupHermesConfigForTeardownTest(t, dataDir, path, script, pristine)
		if err := os.WriteFile(path, []byte(readHookFileForTest(t, path)+"# user edit\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := NewHermesConnector().removeConfigEntriesWithManagedBackup(
			SetupOpts{DataDir: dataDir}, "config.yaml", path, script,
		); err != nil {
			t.Fatalf("remove hook entries: %v", err)
		}
		got := readHookFileForTest(t, path)
		if strings.Contains(got, script) || !strings.Contains(got, "/usr/local/bin/mine") ||
			!strings.Contains(got, "hooks:") || !strings.HasSuffix(got, "# user edit\n") {
			t.Fatalf("config.yaml after teardown =\n%s", got)
		}
	})
}

// setupHermesConfigForTeardownTest writes pristine to path, captures it as
// Setup does, registers DefenseClaw's hooks and records the post-setup hash.
func setupHermesConfigForTeardownTest(t *testing.T, dataDir, path, script, pristine string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(pristine), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := captureManagedFileBackup(dataDir, "hermes", "config.yaml", path); err != nil {
		t.Fatal(err)
	}
	if err := patchHermesHooks(path, script, ""); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(readHookFileForTest(t, path), script) {
		t.Fatalf("fixture: Setup did not register the hook:\n%s", readHookFileForTest(t, path))
	}
	if err := updateManagedFileBackupPostHash(dataDir, "hermes", "config.yaml", path); err != nil {
		t.Fatal(err)
	}
}
