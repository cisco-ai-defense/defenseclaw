// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// A managed hook's tool call carries the first sighting of the directories
// it reaches, an empty directory included, and a SessionStart carries the
// start directories' identities.
func TestResolveConnectorSendsReachedInstructionSighting(t *testing.T) {
	existing, empty := t.TempDir(), t.TempDir()
	file := filepath.Join(existing, "AGENTS.md")
	if err := os.WriteFile(file, []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	patch := "*** Begin Patch\n*** Add File: " + filepath.Join(empty, "AGENTS.md") +
		"\n+new\n*** End Patch"
	body, _ := json.Marshal(map[string]interface{}{
		"hook_event_name": "PreToolUse", "session_id": "live", "cwd": existing,
		"tool_name": "apply_patch", "tool_input": map[string]interface{}{"command": patch},
	})
	targets, ok := Decode(ResolveConnector("codex", "", "PreToolUse", body))
	if !ok {
		t.Fatal("no evidence")
	}
	dirs, files, ok := ReachedInstructions(targets)
	if !ok {
		t.Fatalf("no reached sighting: %v", targets)
	}
	if identity, read := dirs[filepath.Clean(empty)]; !read || identity == "" || identity != DirectoryIdentity(empty) {
		t.Fatalf("the written directory was not sighted: %v", dirs)
	}
	if files[file] != FileIdentity(file) || files[filepath.Join(empty, "AGENTS.md")] != "" {
		t.Fatalf("wrong files: %v", files)
	}

	start, _ := json.Marshal(map[string]interface{}{"hook_event_name": "SessionStart", "session_id": "live", "cwd": empty})
	startFacts, ok := Decode(ResolveConnector("codex", "", "SessionStart", start))
	if !ok {
		t.Fatal("no startup evidence")
	}
	if dirs, _, ok := ReachedInstructions(startFacts); !ok || dirs[filepath.Clean(empty)] != DirectoryIdentity(empty) {
		t.Fatalf("SessionStart did not carry the start directory's identity: %v", startFacts)
	}
}

// A sighting that lists a file outside its directories, or a malformed one,
// makes the whole evidence map invalid.
func TestDecodeRejectsMalformedReachedSighting(t *testing.T) {
	dir := t.TempDir()
	other := t.TempDir()
	for name, sighting := range map[string]string{
		"file outside":  `{"d":{` + reachedTestQuote(dir) + `:""},"f":{` + reachedTestQuote(filepath.Join(other, "AGENTS.md")) + `:"1:2"}}`,
		"not a name":    `{"d":{` + reachedTestQuote(dir) + `:""},"f":{` + reachedTestQuote(filepath.Join(dir, "notes.md")) + `:"1:2"}}`,
		"bad identity":  `{"d":{` + reachedTestQuote(dir) + `:"zz"},"f":{}}`,
		"relative dir":  `{"d":{"rel":""},"f":{}}`,
		"no files list": `{"d":{` + reachedTestQuote(dir) + `:""}}`,
		"no dirs":       `{"d":{},"f":{}}`,
	} {
		encoded, _ := json.Marshal(map[string]string{CWDKey: dir, ReachedInstructionsKey: sighting})
		if _, ok := Decode(base64.RawURLEncoding.EncodeToString(encoded)); ok {
			t.Errorf("%s: accepted %s", name, sighting)
		}
	}
	valid := `{"d":{` + reachedTestQuote(dir) + `:""},"f":{}}`
	encoded, _ := json.Marshal(map[string]string{CWDKey: dir, ReachedInstructionsKey: valid})
	if _, ok := Decode(base64.RawURLEncoding.EncodeToString(encoded)); !ok {
		t.Errorf("rejected an empty sighting %s", valid)
	}
}

func reachedTestQuote(value string) string {
	encoded, _ := json.Marshal(value)
	return string(encoded)
}
