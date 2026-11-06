// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const copilotHookFileWithUserEntry = `{
  "version": 1,
  "hooks": {
    "preToolUse": [
      {"type":"command","bash":"'/Users/u/.defenseclaw/hooks/copilot-hook.sh' --event 'preToolUse'","timeoutSec":30},
      {"type":"command","bash":"/Users/u/bin/my-copilot-hook.sh","timeoutSec":5}
    ],
    "agentStop": [
      {"type":"command","bash":"'/Users/u/.defenseclaw/hooks/copilot-hook.sh' --event 'agentStop'","timeoutSec":30}
    ]
  }
}
`

// A user's own entry in a Copilot hook file survives; DefenseClaw's go, and
// the events left empty go with them.
func TestScrubCopilot_DropsDCKeepsUserEntry(t *testing.T) {
	path := filepath.Join(t.TempDir(), "defenseclaw.json")
	writeFile(t, path, copilotHookFileWithUserEntry)

	changed, err := scrubCopilotFile(path, scrubDefaultMarkers)
	if err != nil {
		t.Fatalf("scrubCopilotFile: %v", err)
	}
	if !changed {
		t.Fatal("expected changed=true")
	}
	out := readFile(t, path)
	if strings.Contains(out, ".defenseclaw/hooks/") {
		t.Errorf("DefenseClaw entry survived:\n%s", out)
	}
	if !strings.Contains(out, "my-copilot-hook.sh") {
		t.Errorf("the user's hook was dropped:\n%s", out)
	}
	if strings.Contains(out, "agentStop") {
		t.Errorf("an emptied event was kept:\n%s", out)
	}
	if changed, err := scrubCopilotFile(path, scrubDefaultMarkers); err != nil || changed {
		t.Fatalf("second scrub = %v, %v; want unchanged", changed, err)
	}
}

// DefenseClaw's own defenseclaw.json holding nothing else is removed, not
// left as an empty document.
func TestScrubCopilot_RemovesOwnFileWhenOnlyDCEntries(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("as root the scrub rewrites in place instead of removing")
	}
	path := filepath.Join(t.TempDir(), "defenseclaw.json")
	writeFile(t, path, `{"version":1,"hooks":{"preToolUse":[{"type":"command","bash":"'/Users/u/.defenseclaw/hooks/copilot-hook.sh' --event 'preToolUse'","timeoutSec":30}]}}
`)
	changed, err := scrubCopilotFile(path, scrubDefaultMarkers)
	if err != nil || !changed {
		t.Fatalf("scrubCopilotFile = %v, %v", changed, err)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("defenseclaw.json still exists: lstat err = %v", err)
	}
}

// A Copilot hook file under another name, or one carrying keys DefenseClaw
// does not write, is only edited.
func TestScrubCopilot_KeepsFileItDoesNotOwnWhole(t *testing.T) {
	dir := t.TempDir()
	cases := map[string]string{
		"other.json":       `{"version":1,"hooks":{"preToolUse":[{"type":"command","bash":"'/Users/u/.defenseclaw/hooks/copilot-hook.sh' --event 'preToolUse'"}]}}`,
		"defenseclaw.json": `{"version":1,"note":"kept","hooks":{"preToolUse":[{"type":"command","bash":"'/Users/u/.defenseclaw/hooks/copilot-hook.sh' --event 'preToolUse'"}]}}`,
	}
	for name, body := range cases {
		path := filepath.Join(dir, name)
		writeFile(t, path, body+"\n")
		if _, err := scrubCopilotFile(path, scrubDefaultMarkers); err != nil {
			t.Fatalf("%s: scrubCopilotFile: %v", name, err)
		}
		out := readFile(t, path)
		if strings.Contains(out, ".defenseclaw/hooks/") {
			t.Errorf("%s: DefenseClaw entry survived:\n%s", name, out)
		}
	}
	if !strings.Contains(readFile(t, filepath.Join(dir, "defenseclaw.json")), `"note": "kept"`) {
		t.Error("a key DefenseClaw does not write was dropped")
	}
}

// The uninstaller reaches the handler through --connector copilot.
func TestScrubCopilot_ConnectorFlagRoutesToHandler(t *testing.T) {
	path := filepath.Join(t.TempDir(), "other.json")
	writeFile(t, path, copilotHookFileWithUserEntry)
	setScrubFlags(t, "copilot", path, false)
	if err := runEnterpriseHooksScrub(enterpriseHooksScrubCmd, nil); err != nil {
		t.Fatalf("runEnterpriseHooksScrub: %v", err)
	}
	if strings.Contains(readFile(t, path), ".defenseclaw/hooks/") {
		t.Fatal("--connector copilot left the DefenseClaw entry")
	}
}
