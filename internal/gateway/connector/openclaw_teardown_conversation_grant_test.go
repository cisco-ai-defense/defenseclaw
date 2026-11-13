// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// openClawGrantFixture is an OpenClaw home with openclaw.json holding
// "before", the managed record of it (as setup takes it) and the plugin
// registered with the conversation-hook grant, the way a gateway start leaves it.
func openClawGrantFixture(t *testing.T, before string) (configPath string, opts SetupOpts) {
	t.Helper()
	dataDir := t.TempDir()
	ocHome := filepath.Join(dataDir, "openclaw-home")
	if err := os.MkdirAll(ocHome, 0o755); err != nil {
		t.Fatal(err)
	}
	OpenClawHomeOverride = ocHome
	t.Cleanup(func() { OpenClawHomeOverride = "" })
	configPath = filepath.Join(ocHome, "openclaw.json")
	if err := os.WriteFile(configPath, []byte(before), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := captureManagedFileBackup(dataDir, "openclaw", "openclaw.json", configPath); err != nil {
		t.Fatal(err)
	}
	if err := patchOpenClawConfig(configPath, filepath.Join(ocHome, "extensions", "defenseclaw"), false, false, true); err != nil {
		t.Fatal(err)
	}
	if err := updateManagedFileBackupPostHash(dataDir, "openclaw", "openclaw.json", configPath); err != nil {
		t.Fatal(err)
	}
	return configPath, SetupOpts{DataDir: dataDir}
}

// OpenClaw saves openclaw.json itself while it runs. Uninstall then cannot put
// the saved bytes back and takes out DefenseClaw's settings member by member;
// the conversation-hook grant setup added goes with them, and everything the
// operator wrote stays (GAP-0986).
func TestOpenClawUninstallOfASavedFileTakesOutTheConversationGrantSetupAdded(t *testing.T) {
	const before = "{\n  gateway: { port: 18789, },\n  plugins: { entries: { 'somebody-else': { enabled: true, }, }, },\n}\n"
	configPath, opts := openClawGrantFixture(t, before)
	if got := mustReadFileString(t, configPath); !strings.Contains(got, "allowConversationAccess") {
		t.Fatalf("setup did not add the grant:\n%s", got)
	}
	saved := strings.Replace(mustReadFileString(t, configPath), "\"gateway\"", "\"meta\": {\"lastTouchedVersion\": \"x\"},\n  \"gateway\"", 1)
	if err := os.WriteFile(configPath, []byte(saved), 0o644); err != nil {
		t.Fatal(err)
	}
	var notice bytes.Buffer
	previous := openClawTeardownNoticeOutput
	openClawTeardownNoticeOutput = &notice
	t.Cleanup(func() { openClawTeardownNoticeOutput = previous })

	if err := NewOpenClawConnector().Teardown(context.Background(), opts); err != nil {
		t.Fatalf("Teardown: %v", err)
	}
	got := mustReadFileString(t, configPath)
	for _, residue := range []string{"allowConversationAccess", "\"defenseclaw\"", "hooks"} {
		if strings.Contains(got, residue) {
			t.Fatalf("uninstall left %q in a saved file:\n%s", residue, got)
		}
	}
	for _, kept := range []string{"lastTouchedVersion", "somebody-else"} {
		if !strings.Contains(got, kept) {
			t.Fatalf("uninstall lost %q:\n%s", kept, got)
		}
	}
	if !strings.Contains(notice.String(), configPath) {
		t.Fatalf("uninstall kept a changed file without saying so: %q", notice.String())
	}
}

// Benign twins: a grant the operator had before setup, and the operator's other
// hook settings, stay; so does an emptied hooks object the operator had.
func TestOpenClawUninstallOfASavedFileKeepsWhatTheOperatorHadUnderHooks(t *testing.T) {
	for name, tc := range map[string]struct {
		before string
		want   []string
		gone   []string
	}{
		"grant the operator set": {
			before: `{"plugins":{"entries":{"defenseclaw":{"hooks":{"allowConversationAccess":true}}}}}` + "\n",
			want:   []string{"allowConversationAccess"},
		},
		"other hook settings": {
			before: `{"plugins":{"entries":{"defenseclaw":{"hooks":{"timeouts":{"before_tool_call":60000}}}}}}` + "\n",
			want:   []string{"timeouts", "before_tool_call"},
			gone:   []string{"allowConversationAccess", "\"enabled\""},
		},
		"empty hooks object": {
			before: `{"plugins":{"entries":{"defenseclaw":{"hooks":{}}}}}` + "\n",
			want:   []string{"\"hooks\""},
			gone:   []string{"allowConversationAccess", "\"enabled\""},
		},
	} {
		t.Run(name, func(t *testing.T) {
			configPath, opts := openClawGrantFixture(t, tc.before)
			saved := strings.Replace(mustReadFileString(t, configPath), "{", "{\"meta\": {\"saved\": true},", 1)
			if err := os.WriteFile(configPath, []byte(saved), 0o644); err != nil {
				t.Fatal(err)
			}
			previous := openClawTeardownNoticeOutput
			openClawTeardownNoticeOutput = &bytes.Buffer{}
			t.Cleanup(func() { openClawTeardownNoticeOutput = previous })
			if err := NewOpenClawConnector().Teardown(context.Background(), opts); err != nil {
				t.Fatalf("Teardown: %v", err)
			}
			got := mustReadFileString(t, configPath)
			for _, w := range tc.want {
				if !strings.Contains(got, w) {
					t.Errorf("lost %q:\n%s", w, got)
				}
			}
			for _, g := range tc.gone {
				if strings.Contains(got, g) {
					t.Errorf("left %q:\n%s", g, got)
				}
			}
			if openClawConfigRegistersDefenseClaw(configPath) {
				t.Errorf("DefenseClaw stays registered:\n%s", got)
			}
		})
	}
}

// With no record of the file before setup nothing shows who wrote the grant,
// so an uninstall of such a file leaves it.
func TestOpenClawUninstallWithoutARecordKeepsTheConversationGrant(t *testing.T) {
	configPath, opts := openClawGrantFixture(t, "{}\n")
	discardManagedFileBackup(opts.DataDir, "openclaw", "openclaw.json")
	if err := uninstallOpenClawExtension(openClawPathsIn(filepath.Dir(configPath)), false, openClawSetupGrantFor(opts.DataDir, "openclaw")); err != nil {
		t.Fatal(err)
	}
	if got := mustReadFileString(t, configPath); !strings.Contains(got, "allowConversationAccess") {
		t.Fatalf("a grant of unknown origin was removed:\n%s", got)
	}
}

// The plain JSON path (the file has no comments or JSON5 spelling) takes the
// same members out.
func TestOpenClawUninstallOfAPlainSavedFileTakesOutTheConversationGrant(t *testing.T) {
	configPath, opts := openClawGrantFixture(t, "{\"gateway\":{\"port\":18789}}\n")
	saved := strings.Replace(mustReadFileString(t, configPath), "{", "{\"meta\": {\"saved\": true},", 1)
	if err := os.WriteFile(configPath, []byte(saved), 0o644); err != nil {
		t.Fatal(err)
	}
	previous := openClawTeardownNoticeOutput
	openClawTeardownNoticeOutput = &bytes.Buffer{}
	t.Cleanup(func() { openClawTeardownNoticeOutput = previous })
	if err := NewOpenClawConnector().Teardown(context.Background(), opts); err != nil {
		t.Fatalf("Teardown: %v", err)
	}
	got := mustReadFileString(t, configPath)
	if strings.Contains(got, "allowConversationAccess") || strings.Contains(got, "defenseclaw") || !strings.Contains(got, "\"saved\"") {
		t.Fatalf("saved plain file after uninstall:\n%s", got)
	}
}

// OpenClaw saves the file in its own spelling (comments, single quotes, bare
// keys, trailing commas); the member-level removal cuts the text, so that
// spelling stays.
func TestOpenClawUninstallOfASavedJSON5FileKeepsItsSpellingAndTakesOutTheGrant(t *testing.T) {
	configPath, opts := openClawGrantFixture(t, "{}\n")
	const saved = "// saved by OpenClaw\n{\n  meta: { a: 1, },\n  plugins: {\n    allow: ['defenseclaw', 'other'],\n" +
		"    entries: {\n      'somebody-else': { enabled: true, },\n" +
		"      defenseclaw: { enabled: true, hooks: { allowConversationAccess: true, timeouts: { x: 1, }, }, },\n    },\n  },\n}\n"
	if err := os.WriteFile(configPath, []byte(saved), 0o644); err != nil {
		t.Fatal(err)
	}
	previous := openClawTeardownNoticeOutput
	openClawTeardownNoticeOutput = &bytes.Buffer{}
	t.Cleanup(func() { openClawTeardownNoticeOutput = previous })
	if err := NewOpenClawConnector().Teardown(context.Background(), opts); err != nil {
		t.Fatalf("Teardown: %v", err)
	}
	got := mustReadFileString(t, configPath)
	if strings.Contains(got, "allowConversationAccess") {
		t.Fatalf("the grant stayed:\n%s", got)
	}
	for _, kept := range []string{"// saved by OpenClaw", "meta: { a: 1, }", "'somebody-else'", "'other'", "timeouts: { x: 1, }"} {
		if !strings.Contains(got, kept) {
			t.Fatalf("uninstall changed the spelling around %q:\n%s", kept, got)
		}
	}
}

// Setup runs again on every gateway start. A second setup over a file OpenClaw
// saved must keep the record of the file from before setup, so uninstall still
// knows the conversation-hook grant is DefenseClaw's to take out (GAP-0986).
func TestOpenClawRepeatedSetupOverASavedFileKeepsTheGrantOwnership(t *testing.T) {
	for name, saves := range map[string]int{"one setup after the save": 1, "two setups after the save": 2} {
		t.Run(name, func(t *testing.T) {
			configPath, opts := openClawGrantFixture(t, "{\n  gateway: { port: 18789, },\n}\n")
			saved := strings.Replace(mustReadFileString(t, configPath), "{", "{\"meta\": {\"saved\": true},", 1)
			if err := os.WriteFile(configPath, []byte(saved), 0o644); err != nil {
				t.Fatal(err)
			}
			extDir := filepath.Join(filepath.Dir(configPath), "extensions", "defenseclaw")
			for i := 0; i < saves; i++ {
				exactRestore, err := openClawSnapshotUsable(opts.DataDir, "openclaw", configPath)
				if err != nil {
					t.Fatal(err)
				}
				if exactRestore {
					t.Fatal("a saved file must not be offered the exact restore")
				}
				if err := patchOpenClawConfig(configPath, extDir, false, false, true); err != nil {
					t.Fatal(err)
				}
			}
			previous := openClawTeardownNoticeOutput
			openClawTeardownNoticeOutput = &bytes.Buffer{}
			t.Cleanup(func() { openClawTeardownNoticeOutput = previous })
			if err := NewOpenClawConnector().Teardown(context.Background(), opts); err != nil {
				t.Fatalf("Teardown: %v", err)
			}
			got := mustReadFileString(t, configPath)
			for _, residue := range []string{"allowConversationAccess", "\"defenseclaw\"", "hooks"} {
				if strings.Contains(got, residue) {
					t.Fatalf("uninstall left %q after a repeated setup:\n%s", residue, got)
				}
			}
			if !strings.Contains(got, "\"saved\"") {
				t.Fatalf("uninstall lost the saved member:\n%s", got)
			}
		})
	}
}

// The benign twin: a grant the operator had before setup survives repeated setups and uninstall.
func TestOpenClawRepeatedSetupOverASavedFileKeepsAnOperatorGrant(t *testing.T) {
	configPath, opts := openClawGrantFixture(t, `{"plugins":{"entries":{"defenseclaw":{"hooks":{"allowConversationAccess":true}}}}}`+"\n")
	saved := strings.Replace(mustReadFileString(t, configPath), "{", "{\"meta\": {\"saved\": true},", 1)
	if err := os.WriteFile(configPath, []byte(saved), 0o644); err != nil {
		t.Fatal(err)
	}
	extDir := filepath.Join(filepath.Dir(configPath), "extensions", "defenseclaw")
	if _, err := openClawSnapshotUsable(opts.DataDir, "openclaw", configPath); err != nil {
		t.Fatal(err)
	}
	if err := patchOpenClawConfig(configPath, extDir, false, false, true); err != nil {
		t.Fatal(err)
	}
	previous := openClawTeardownNoticeOutput
	openClawTeardownNoticeOutput = &bytes.Buffer{}
	t.Cleanup(func() { openClawTeardownNoticeOutput = previous })
	if err := NewOpenClawConnector().Teardown(context.Background(), opts); err != nil {
		t.Fatalf("Teardown: %v", err)
	}
	if got := mustReadFileString(t, configPath); !strings.Contains(got, "allowConversationAccess") {
		t.Fatalf("a grant the operator wrote was removed:\n%s", got)
	}
}
