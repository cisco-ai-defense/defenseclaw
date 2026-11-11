// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
)

// TestResolveConnectorOversizePatchTextIsNotReadAsShell pins that the hook
// client does not read the text of an apply_patch envelope over the analysis
// string limit as a shell command: it lists the files the envelope names and
// not the redirect targets of a line of file content, and it does not spend
// seconds on an ordinary 889 KB patch (GAP-1008). The same lines in a patch
// under the limit keep the reading they had.
func TestResolveConnectorOversizePatchTextIsNotReadAsShell(t *testing.T) {
	// The directive and the redirect are shell text: a Windows host spells the
	// folder with slashes there, because a backslash is a shell escape.
	home := filepath.ToSlash(t.TempDir())
	cwd := home + "/project"
	target := cwd + "/notes.txt"
	content := cwd + "/redirect-in-file-content.txt"
	for _, row := range []struct {
		name  string
		lines int
		read  bool
	}{
		{"under the limit", 20, true},
		{"over the limit", 20000, false},
	} {
		var body strings.Builder
		body.WriteString("*** Begin Patch\n*** Add File: " + target + "\n")
		body.WriteString("+echo done > " + content + "\n")
		for i := 0; i < row.lines; i++ {
			fmt.Fprintf(&body, "+line %d padding padding padding padding\n", i)
		}
		body.WriteString("*** End Patch\n")
		payload, err := json.Marshal(map[string]any{"tool_name": "apply_patch", "cwd": cwd,
			"tool_input": map[string]any{"command": body.String()}})
		if err != nil {
			t.Fatal(err)
		}
		targets, ok := Decode(ResolveConnector("codex", "", "PreToolUse", payload))
		if !ok {
			t.Fatalf("%s: no evidence", row.name)
		}
		if !targetListed(targets, target) {
			t.Errorf("%s: targets %v, want %s", row.name, targets, target)
		}
		if listed := targetListed(targets, content); listed != row.read {
			t.Errorf("%s: redirect target of a content line listed = %t, want %t (targets %v)", row.name, listed, row.read, targets)
		}
	}
}
