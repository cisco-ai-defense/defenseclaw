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

func TestInstructionStartupEvidencePinsExistingFileIdentity(t *testing.T) {
	project := t.TempDir()
	file := filepath.Join(project, "AGENTS.md")
	start := func() map[string]string {
		t.Helper()
		body, err := json.Marshal(map[string]string{
			"hook_event_name": "SessionStart", "session_id": "same", "cwd": project,
		})
		if err != nil {
			t.Fatal(err)
		}
		targets, ok := Decode(ResolveConnector("codex", "", "SessionStart", body))
		if !ok {
			t.Fatal("missing or invalid startup evidence")
		}
		files, ok := StartupFiles(targets)
		if !ok {
			t.Fatal("startup map was not decoded")
		}
		return files
	}
	if files := start(); files[file] != "" {
		t.Fatalf("absent file got startup identity: %#v", files)
	}
	if err := os.WriteFile(file, []byte("new\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	firstID := FileIdentity(file)
	if firstID == "" || start()[file] != firstID {
		t.Fatalf("existing file identity not captured: %q", firstID)
	}
	if err := os.Rename(file, filepath.Join(project, "saved.txt")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte("replacement\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if nextID := FileIdentity(file); nextID == "" || nextID == firstID {
		t.Fatalf("replacement reused startup identity: %q then %q", firstID, nextID)
	}
}

func TestInstructionStartupEvidenceRejectsInvalidIdentity(t *testing.T) {
	for _, raw := range []string{
		`{"/repo/AGENTS.md":"../../fake"}`,
		`{"relative/AGENTS.md":"1:2"}`,
		`{"/repo/report.txt":"1:2"}`,
	} {
		body, err := json.Marshal(map[string]string{StartupFilesKey: raw})
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := Decode(base64.RawURLEncoding.EncodeToString(body)); ok {
			t.Fatalf("accepted invalid startup identity %s", raw)
		}
	}
}

func TestInstructionStartupEvidenceForConnectorLifecycleSpellings(t *testing.T) {
	project := t.TempDir()
	file := filepath.Join(project, "AGENTS.md")
	if err := os.WriteFile(file, []byte("startup\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, event := range []string{"SessionStart", "session_start", "on_session_start", "on_session_reset", "sessionCreated"} {
		t.Run(event, func(t *testing.T) {
			body, err := json.Marshal(map[string]string{"hook_event_name": event, "session_id": "same", "cwd": project})
			if err != nil {
				t.Fatal(err)
			}
			targets, ok := Decode(ResolveConnector("hermes", "", event, body))
			if !ok {
				t.Fatal("startup event did not capture file evidence")
			}
			files, ok := StartupFiles(targets)
			if !ok || files[file] != FileIdentity(file) {
				t.Fatalf("startup evidence = %#v, valid=%t", files, ok)
			}
		})
	}
}
