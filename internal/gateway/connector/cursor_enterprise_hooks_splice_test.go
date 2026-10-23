// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"bytes"
	"encoding/json"
	"testing"
)

const spliceTestAdapter = `C:\ProgramData\Cursor\defenseclaw-hook.ps1`

func spliceTestOwnedEntry(t *testing.T, command string, failClosed bool) string {
	t.Helper()
	entry, err := json.Marshal(map[string]any{
		"type": "command", "command": command,
		"timeout": windowsCursorEnterpriseHookTimeoutSeconds, "failClosed": failClosed,
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(entry)
}

// The guard rebuild edits only DefenseClaw's entries in the shared machine
// hooks.json: every other entry, key and value keeps its exact bytes, and the
// result is the document the merge renders.
func TestSpliceWindowsCursorEnterpriseHooksKeepsForeignBytes(t *testing.T) {
	command, legacy, err := windowsCursorEnterpriseHookCommands(spliceTestAdapter)
	if err != nil {
		t.Fatal(err)
	}
	previous := previousWindowsCursorEnterpriseHookCommand(spliceTestAdapter)
	foreignA := `{"command": "C:\\Tools\\audit.cmd 2>&1 && echo \u00e9", "timeout": 5.0, "type":"command"}`
	foreignB := `{ "type" : "command" , "command" : "admin <one> & two" }`
	extra := `"x-admin": {"note": "keep  me", "n": 1e3}`
	for _, test := range []struct {
		name    string
		doc     string
		foreign []string
	}{
		{
			name: "registration missing, tabs and unsorted keys",
			doc: "{\n\t\"hooks\": {\n\t\t\"beforeShellExecution\": [ " + foreignA + " ],\n\t\t\"adminEvent\":[" + foreignB +
				"]\n\t},\n\t\"version\": 1,\n\t" + extra + "\n}\n",
			foreign: []string{foreignA, `"adminEvent":[` + foreignB + `]`, extra, "\n\t\"version\": 1,\n\t"},
		},
		{
			name: "registration fails open beside foreign entries",
			doc: `{"version":1,"hooks":{"stop":[` + foreignB + `,` + spliceTestOwnedEntry(t, command, false) +
				`],"beforeShellExecution":[` + spliceTestOwnedEntry(t, command, false) + `, ` + foreignA + `]},` + extra + `}`,
			foreign: []string{foreignA, foreignB, extra},
		},
		{
			name: "legacy and previous commands are replaced",
			doc: `{"version":1,"hooks":{"preToolUse":[` + spliceTestOwnedEntry(t, legacy, true) + `,` + foreignB + `,` +
				spliceTestOwnedEntry(t, previous, true) + `]}}`,
			foreign: []string{foreignB},
		},
		{
			name: "retired event holding only DefenseClaw is dropped",
			doc: `{"version":1,"hooks":{"afterAgentThought":[` + spliceTestOwnedEntry(t, command, true) +
				`],"adminEvent":[` + foreignB + `]}}`,
			foreign: []string{`"adminEvent":[` + foreignB + `]`},
		},
		{
			name:    "retired event keeps a foreign entry",
			doc:     `{"version":1,"hooks":{"afterAgentThought":[` + foreignA + `,` + spliceTestOwnedEntry(t, command, true) + `]}}`,
			foreign: []string{`"afterAgentThought":[` + foreignA + `]`},
		},
		{name: "version and hooks missing", doc: `{` + extra + `}`, foreign: []string{extra}},
		{name: "version and hooks null", doc: `{"version":null,"hooks":null,` + extra + `}`, foreign: []string{extra}},
		{
			name:    "managed and foreign events null",
			doc:     `{"version":1,"hooks":{"stop":null,"adminEvent":null}}`,
			foreign: []string{`"adminEvent":null`},
		},
		{
			name:    "empty arrays",
			doc:     `{"version":1,"hooks":{"stop":[],"adminEvent":[]}}`,
			foreign: []string{`"adminEvent":[]`},
		},
	} {
		for _, failMode := range []string{"closed", "open"} {
			t.Run(test.name+"/"+failMode, func(t *testing.T) {
				merged, err := MergeWindowsCursorEnterpriseHooks([]byte(test.doc), spliceTestAdapter, failMode)
				if err != nil {
					t.Fatal(err)
				}
				spliced, err := SpliceWindowsCursorEnterpriseHooks([]byte(test.doc), spliceTestAdapter, failMode)
				if err != nil {
					t.Fatal(err)
				}
				if !WindowsCursorEnterpriseHooksSemanticallyEqual(spliced, merged) {
					t.Fatalf("splice differs from the merge:\n%s\nwant\n%s", spliced, merged)
				}
				if err := VerifyWindowsCursorEnterpriseHooks(spliced, spliceTestAdapter, failMode); err != nil {
					t.Fatalf("spliced registration does not verify: %v\n%s", err, spliced)
				}
				for _, foreign := range test.foreign {
					if !bytes.Contains(spliced, []byte(foreign)) {
						t.Fatalf("foreign bytes %q changed:\n%s", foreign, spliced)
					}
				}
				again, err := SpliceWindowsCursorEnterpriseHooks(spliced, spliceTestAdapter, failMode)
				if err != nil || !bytes.Equal(again, spliced) {
					t.Fatalf("second splice changed the document (err %v):\n%s", err, again)
				}
			})
		}
	}
}

func TestSpliceWindowsCursorEnterpriseHooksKeepsAMergedDocument(t *testing.T) {
	merged, err := MergeWindowsCursorEnterpriseHooks(
		[]byte(`{"version":1,"hooks":{"adminEvent":[{"command":"admin"}]}}`), spliceTestAdapter, "closed")
	if err != nil {
		t.Fatal(err)
	}
	spliced, err := SpliceWindowsCursorEnterpriseHooks(merged, spliceTestAdapter, "closed")
	if err != nil || !bytes.Equal(spliced, merged) {
		t.Fatalf("splice rewrote a merged document (err %v):\n%s", err, spliced)
	}
	fresh, err := SpliceWindowsCursorEnterpriseHooks(nil, spliceTestAdapter, "closed")
	if err != nil {
		t.Fatal(err)
	}
	if want, _ := MergeWindowsCursorEnterpriseHooks(nil, spliceTestAdapter, "closed"); !bytes.Equal(fresh, want) {
		t.Fatalf("a missing hooks.json renders differently from the merge:\n%s", fresh)
	}
}

func TestSpliceWindowsCursorEnterpriseHooksRefusesWhatMergeRefuses(t *testing.T) {
	for _, doc := range []string{
		`{"version":2,"hooks":{}}`,
		`{"version":1,"hooks":{"stop":{"command":"admin"}}}`,
		`{"version":1,"hooks":[]}`,
		`{ not json`,
	} {
		if _, err := SpliceWindowsCursorEnterpriseHooks([]byte(doc), spliceTestAdapter, "closed"); err == nil {
			t.Fatalf("splice accepted %s", doc)
		}
	}
}

// A document the splice cannot edit in place gets the merged render, which
// keeps the same hooks.
func TestSpliceWindowsCursorEnterpriseHooksFallsBackToTheMerge(t *testing.T) {
	for _, doc := range []string{
		`{"version":1,"hooks":{"adminEvent":[{"command":"a"}]},"hooks":{"adminEvent":[{"command":"b"}]}}`,
		`{"version":1,"hooks":{"adminEvent":[{"command":"a"}],"adminEvent":[{"command":"b"}]}}`,
		`null`,
	} {
		merged, err := MergeWindowsCursorEnterpriseHooks([]byte(doc), spliceTestAdapter, "closed")
		if err != nil {
			t.Fatal(err)
		}
		spliced, err := SpliceWindowsCursorEnterpriseHooks([]byte(doc), spliceTestAdapter, "closed")
		if err != nil || !bytes.Equal(spliced, merged) {
			t.Fatalf("splice of %s (err %v):\n%s\nwant\n%s", doc, err, spliced, merged)
		}
	}
}
