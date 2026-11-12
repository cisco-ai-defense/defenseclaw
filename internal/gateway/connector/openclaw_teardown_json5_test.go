// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// json5NeverSetUp is a JSON5 openclaw.json that holds nothing of DefenseClaw's.
const json5NeverSetUp = "\ufeff// my openclaw config\n" +
	"{\n" +
	"  /* gateway */ port: 0x1F90, // hex\n" +
	"  note: 'a \\\n   continued line', " +
	"  plugins: {\n" +
	"    allow: [\n      'other', // keep\n    ],\n" +
	"    entries: { other: { enabled: true, }, },\n" +
	"    load: { paths: ['/opt/other',], },\n" +
	"  },\n" +
	"  approvals: { plugin: { mode: 'ask', enabled: true, }, },\n" +
	"}"

func writeOpenClawText(t *testing.T, ocHome, text string) string {
	t.Helper()
	if err := os.MkdirAll(ocHome, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(ocHome, "openclaw.json")
	if err := os.WriteFile(path, []byte(text), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func readOpenClawText(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// A teardown that removes nothing leaves a JSON5 openclaw.json byte for byte,
// whichever way the file is spelled and whether or not the approvals clean-up
// applies (GAP-0937).
func TestOpenClawTeardownLeavesAJSON5FileDefenseClawNeverSetUp(t *testing.T) {
	spellings := map[string]string{
		"comments, hex, quotes, BOM": json5NeverSetUp,
		"trailing newline":           strings.TrimPrefix(json5NeverSetUp, "\ufeff") + "\n",
		"CRLF lines":                 strings.ReplaceAll(json5NeverSetUp, "\n", "\r\n"),
		"plain JSON":                 "{\"plugins\": {\"allow\": [\"other\"]}}",
		"empty object":               "{}",
		"no plugins block":           "// only a comment\n{ gateway: { port: 18789 }, }\n",
	}
	for name, text := range spellings {
		for _, dropApprovals := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/dropApprovals=%v", name, dropApprovals), func(t *testing.T) {
				ocHome := filepath.Join(t.TempDir(), "openclaw-home")
				path := writeOpenClawText(t, ocHome, text)
				if err := uninstallOpenClawExtension(ocHome, dropApprovals, openClawSetupGrant{}); err != nil {
					t.Fatalf("uninstallOpenClawExtension: %v", err)
				}
				if got := readOpenClawText(t, path); got != text {
					t.Fatalf("teardown rewrote a file it had nothing to remove from:\n got %q\nwant %q", got, text)
				}
			})
		}
	}
}

// The connector teardown with no pre-setup snapshot takes the same path.
func TestOpenClawConnectorTeardownWithoutSnapshotLeavesAJSON5File(t *testing.T) {
	dataDir := t.TempDir()
	ocHome := filepath.Join(dataDir, "openclaw-home")
	OpenClawHomeOverride = ocHome
	defer func() { OpenClawHomeOverride = "" }()
	path := writeOpenClawText(t, ocHome, json5NeverSetUp)

	if err := NewOpenClawConnector().Teardown(context.Background(), SetupOpts{DataDir: dataDir, ManagedEnterprise: true}); err != nil {
		t.Fatalf("Teardown: %v", err)
	}
	if got := readOpenClawText(t, path); got != json5NeverSetUp {
		t.Fatalf("teardown rewrote a JSON5 file DefenseClaw never set up: %q", got)
	}
}

const json5SetUp = "// my openclaw config\n" +
	"{\n" +
	"  /* gateway */ port: 0x1F90,\n" +
	"  plugins: {\n" +
	"    allow: [\n" +
	"      'other', // keep\n" +
	"      'defenseclaw',\n" +
	"    ],\n" +
	"    entries: {\n" +
	"      other: { enabled: true, },\n" +
	"      defenseclaw: { enabled: true, hooks: { allowConversationAccess: true } },\n" +
	"    },\n" +
	"    load: { paths: ['/opt/other', '/home/u/.openclaw/extensions/defenseclaw',], },\n" +
	"  },\n" +
	"  approvals: { plugin: { enabled: true, mode: 'session' } },\n" +
	"  tail: 'x', // end\n" +
	"}\n"

const json5SetUpTornDown = "// my openclaw config\n" +
	"{\n" +
	"  /* gateway */ port: 0x1F90,\n" +
	"  plugins: {\n" +
	"    allow: [\n" +
	"      'other', // keep\n" +
	"    ],\n" +
	"    entries: {\n" +
	"      other: { enabled: true, },\n" +
	"      defenseclaw: { hooks: { allowConversationAccess: true } },\n" +
	"    },\n" +
	"    load: { paths: ['/opt/other', ], },\n" +
	"  },\n" +
	"  tail: 'x', // end\n" +
	"}\n"

// A teardown that does remove DefenseClaw's settings from a JSON5 file cuts
// those members out of the text: comments, quoting, key order and the
// operator's own entries stay.
func TestOpenClawTeardownTakesOnlyDefenseClawSettingsOutOfAJSON5File(t *testing.T) {
	ocHome := filepath.Join(t.TempDir(), "openclaw-home")
	path := writeOpenClawText(t, ocHome, json5SetUp)
	if err := uninstallOpenClawExtension(ocHome, true, openClawSetupGrant{}); err != nil {
		t.Fatalf("uninstallOpenClawExtension: %v", err)
	}
	if got := readOpenClawText(t, path); got != json5SetUpTornDown {
		t.Fatalf("teardown changed more than the DefenseClaw settings:\n got %q\nwant %q", got, json5SetUpTornDown)
	}
	if openClawConfigRegistersDefenseClaw(path) {
		t.Fatal("teardown left the DefenseClaw plugin registered")
	}
}

// An entry that holds only DefenseClaw's key goes whole, even when it is the
// last member and has no comma of its own, and a one-line file stays one line.
func TestOpenClawTeardownRemovesTheLastMemberAndTheCommaBeforeIt(t *testing.T) {
	cases := []struct{ name, in, want string }{
		{
			"last member without comma",
			"{\n  plugins: {\n    allow: ['defenseclaw'],\n    entries: {\n      other: {},\n      defenseclaw: { enabled: true }\n    }\n  }\n}\n",
			"{\n  plugins: {\n    allow: [],\n    entries: {\n      other: {}\n    }\n  }\n}\n",
		},
		{
			"one line",
			"{plugins:{allow:['a','defenseclaw'],entries:{defenseclaw:{enabled:true}}}}",
			"{plugins:{allow:['a'],entries:{}}}",
		},
		{
			"only the operator keys of the entry are left",
			"{ plugins: { entries: { defenseclaw: { enabled: true, config: { k: 1 } } } } }",
			"{ plugins: { entries: { defenseclaw: { config: { k: 1 } } } } }",
		},
		{
			"human approvals block with other approvals keys keeps the others",
			"{ approvals: { exec: { x: 1 }, plugin: { enabled: true, mode: \"session\" } } }",
			"{ approvals: { exec: { x: 1 } } }",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ocHome := filepath.Join(t.TempDir(), "openclaw-home")
			path := writeOpenClawText(t, ocHome, tc.in)
			if err := uninstallOpenClawExtension(ocHome, true, openClawSetupGrant{}); err != nil {
				t.Fatalf("uninstallOpenClawExtension: %v", err)
			}
			if got := readOpenClawText(t, path); got != tc.want {
				t.Fatalf("got %q\nwant %q", got, tc.want)
			}
		})
	}
}

// The restore path's approvals clean-up leaves a file without the block alone
// and removes only the block from one that has it.
func TestOpenClawApprovalsCleanupKeepsTheRestOfAJSON5File(t *testing.T) {
	ocHome := filepath.Join(t.TempDir(), "openclaw-home")
	path := writeOpenClawText(t, ocHome, json5NeverSetUp)
	if err := dropDefenseClawPluginApprovalsFile(path); err != nil {
		t.Fatal(err)
	}
	if got := readOpenClawText(t, path); got != json5NeverSetUp {
		t.Fatalf("approvals clean-up rewrote a file without the block: %q", got)
	}

	with := "// c\n{\n  a: 1, // one\n  approvals: { plugin: { enabled: true, mode: 'session' }, },\n  b: 2,\n}\n"
	path = writeOpenClawText(t, ocHome, with)
	if err := dropDefenseClawPluginApprovalsFile(path); err != nil {
		t.Fatal(err)
	}
	if got, want := readOpenClawText(t, path), "// c\n{\n  a: 1, // one\n  b: 2,\n}\n"; got != want {
		t.Fatalf("got %q\nwant %q", got, want)
	}
}
