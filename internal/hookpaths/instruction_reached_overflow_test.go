// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// A start directory whose full sighting (its parents and their .claude
// folders) does not fit in the evidence header still sends its own
// identity, on the SessionStart and on a tool call, so the gateway carries
// the first record of that directory across its other spellings.
func TestReachedEvidenceKeepsTheStartDirectoryPastTheHeaderBound(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("a POSIX symlink chain")
	}
	root := t.TempDir()
	home := filepath.Join(root, "home")
	project := filepath.Join(home, "p")
	if err := os.MkdirAll(project, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	for _, variable := range InstructionHomeVariables {
		t.Setenv(variable, "")
	}
	deep := home
	for index := range 130 {
		deep = filepath.Join(deep, fmt.Sprintf("d%04d", index))
	}
	if err := os.MkdirAll(deep, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(deep, "lnk")
	if err := os.Symlink(project, link); err != nil {
		t.Fatal(err)
	}
	if len(link) > MaxWriteTargetPathBytes {
		t.Skip("the temporary directory is too long for the deep spelling")
	}
	if full := reachedEvidence(InstructionDirectories(link, home)); len(full) <= maxEncodedTargets {
		t.Fatalf("the full sighting fits (%d bytes): the test does not reach the bound", len(full))
	}
	want := DirectoryIdentity(project)
	if want == "" {
		t.Fatal("no identity for the project")
	}
	start, err := json.Marshal(map[string]interface{}{"hook_event_name": "SessionStart", "session_id": "s", "cwd": link})
	if err != nil {
		t.Fatal(err)
	}
	call, err := json.Marshal(map[string]interface{}{
		"hook_event_name": "PreToolUse", "session_id": "s", "cwd": link,
		"tool_name": "Bash", "tool_input": map[string]interface{}{"command": "printf x >> AGENTS.md"},
	})
	if err != nil {
		t.Fatal(err)
	}
	for name, evidence := range map[string]string{
		"SessionStart": ResolveConnector("codex", "", "SessionStart", start),
		"PreToolUse":   ResolveConnector("codex", "", "PreToolUse", call),
	} {
		facts, ok := Decode(evidence)
		if !ok {
			t.Fatalf("%s: no evidence", name)
		}
		directories, _, ok := ReachedInstructions(facts)
		if !ok || directories[link] != want {
			t.Fatalf("%s: the start directory's identity is missing: %v %v", name, ok, directories[link])
		}
	}
}
