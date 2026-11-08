// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

// A vendor file the operator re-saved after setup (the whole JSON written
// again in another layout, DefenseClaw entries included) holds more than the
// setup left. A rollback keeps that operator content and removes only the
// DefenseClaw entries; the untouched file still goes back byte for byte.
func TestConnectorPruneOrphansRollbackKeepsReserializedOperatorEdit(t *testing.T) {
	for _, tc := range []struct {
		name       string
		reserialze bool
	}{
		{"untouched file restores exactly", false},
		{"re-saved file with an added operator entry", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := testenv.PrivateTempDir(t)
			t.Setenv("HOME", root)
			t.Setenv("USERPROFILE", root)
			dataDir := filepath.Join(root, ".defenseclaw")
			defer withConnectorState(t, dataDir, "codex")()
			path := filepath.Join(root, ".cursor", "hooks.json")
			if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
				t.Fatal(err)
			}
			initial := []byte("{\n  \"version\": 1,\n  \"hooks\": {\n    \"stop\": [{\"command\": \"echo operator\"}]\n  }\n}\n")
			if err := os.WriteFile(path, initial, 0o600); err != nil {
				t.Fatal(err)
			}
			conn := connector.NewCursorConnector()
			if err := conn.Setup(context.Background(), connector.SetupOpts{
				DataDir: dataDir, APIAddr: "127.0.0.1:18970", APIToken: "test-token",
			}); err != nil {
				t.Fatalf("cursor setup: %v", err)
			}
			if tc.reserialze {
				installed, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				var doc map[string]any
				if err := json.Unmarshal(installed, &doc); err != nil {
					t.Fatal(err)
				}
				hooks := doc["hooks"].(map[string]any)
				hooks["afterFileEdit"] = []any{map[string]any{"command": "echo operator-after-setup"}}
				edited, err := json.MarshalIndent(doc, "", "    ")
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, append(edited, "\r\n"...), 0o600); err != nil {
					t.Fatal(err)
				}
				// Any later Setup (a repair, a mode change, a gateway start)
				// merges over the edited file; it must not take the edit for
				// DefenseClaw own output.
				if err := conn.Setup(context.Background(), connector.SetupOpts{
					DataDir: dataDir, APIAddr: "127.0.0.1:18970", APIToken: "test-token",
				}); err != nil {
					t.Fatalf("cursor setup again: %v", err)
				}
			}
			saved := filepath.Join(root, "saved")
			if err := os.Rename(dataDir, saved); err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(filepath.Join(dataDir, "previous"), 0o700); err != nil {
				t.Fatal(err)
			}
			saved = filepath.Join(dataDir, "previous", "data")
			if err := os.Rename(filepath.Join(root, "saved"), saved); err != nil {
				t.Fatal(err)
			}
			stdout, stderr, exitCode := runConnectorCmd(t, "prune-orphans", "--connector", "cursor", "--rollback-backups-dir", saved)
			if exitCode != 0 || strings.TrimSpace(stderr) != "" {
				t.Fatalf("prune-orphans: exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
			}
			after, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if !tc.reserialze {
				if !bytes.Equal(after, initial) {
					t.Fatalf("untouched hooks.json after rollback = %q, want %q", after, initial)
				}
				return
			}
			if !bytes.Contains(after, []byte("operator-after-setup")) || !bytes.Contains(after, []byte("echo operator")) ||
				strings.Contains(string(after), "cursor-hook") {
				t.Fatalf("re-saved hooks.json after rollback = %q (stdout %q)", after, stdout)
			}
		})
	}
}
