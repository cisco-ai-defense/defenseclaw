// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"bytes"
	"testing"
)

// p0 GAP-1242: a comment the user appends at the very end of config.toml,
// right after a table DefenseClaw renders again ([otel], [hooks]) or removes,
// survives setup, a repeated setup and teardown.
func TestCodexOwnedEditKeepsACommentAtTheEndOfTheFile(t *testing.T) {
	const comment = "# added by user after setup\r\n"
	before := []byte("\xef\xbb\xbfmodel = \"gpt-5\"\r\n[hooks]\r\n[[hooks.Stop]]\r\nmatcher = '*'\r\n" +
		"[otel]\r\nenvironment = \"old\"\r\n" + comment)
	for name, desired := range map[string]map[string]interface{}{
		"setup": {
			"hooks": map[string]interface{}{"Stop": []string{"owned"}},
			"otel":  map[string]interface{}{"environment": "dev"},
		},
		"teardown": {},
	} {
		after, err := editCodexOwnedTOML(before, desired)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !bytes.HasPrefix(after, []byte{0xef, 0xbb, 0xbf}) || bytes.Contains(after, []byte("matcher = '*'")) {
			t.Fatalf("%s: BOM lost or the old product hook kept:\n%q", name, after)
		}
		// The next setup keeps the now-current [otel] bytes and renders
		// [hooks] after them; from then on the file no longer changes.
		second, err := editCodexOwnedTOML(after, desired)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		third, err := editCodexOwnedTOML(second, desired)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		for _, edited := range [][]byte{after, second} {
			if bytes.Count(edited, []byte(comment)) != 1 {
				t.Fatalf("%s: the end-of-file comment was not kept exactly once:\n%q", name, edited)
			}
		}
		if !bytes.Equal(third, second) {
			t.Fatalf("%s: a repeated edit changed the file:\nsecond %q\nthird  %q", name, second, third)
		}
		var decoded map[string]interface{}
		if err := parseCodexTOML(after, &decoded); err != nil {
			t.Fatalf("%s: edited Codex TOML is invalid: %v", name, err)
		}
	}
}
