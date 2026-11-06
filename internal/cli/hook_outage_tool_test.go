// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOpenClawOutageToolKeepsProtectedTargetsClosed(t *testing.T) {
	home := t.TempDir()
	old := outageAccountHome
	outageAccountHome = func() string { return home }
	t.Cleanup(func() { outageAccountHome = old })
	protected := filepath.Join(home, ".defenseclaw", "config.yaml")
	if err := os.MkdirAll(filepath.Dir(protected), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(protected, []byte("guardrail: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(home, "config-alias")
	if err := os.Symlink(protected, alias); err != nil {
		t.Fatal(err)
	}
	custom := filepath.Join(t.TempDir(), "state")
	if err := os.MkdirAll(custom, 0o700); err != nil {
		t.Fatal(err)
	}
	customConfig := filepath.Join(custom, "config.yaml")
	if err := os.WriteFile(customConfig, []byte("guardrail: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	customAlias := filepath.Join(home, "custom-alias")
	if err := os.Symlink(customConfig, customAlias); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name    string
		args    map[string]interface{}
		dataDir string
		want    string
	}{
		{"ordinary command", map[string]interface{}{"command": "date"}, "", "open"},
		{"direct write", map[string]interface{}{"command": "printf x >> ~/.defenseclaw/config.yaml"}, "", "protected"},
		{"known home write", map[string]interface{}{"command": `printf x >> "$HOME/.defenseclaw/config.yaml"`}, "", "protected"},
		{"known local value", map[string]interface{}{"command": `target="$HOME/.defenseclaw/config.yaml"; printf x >> "$target"`}, "", "protected"},
		{"linked write", map[string]interface{}{"command": "printf x >> " + alias}, "", "protected"},
		{"nested command", map[string]interface{}{"request": map[string]interface{}{"command": `printf x >> "$HOME/.defenseclaw/config.yaml"`}}, "", "protected"},
		{"direct path", map[string]interface{}{"path": protected}, "", "protected"},
		{"ordinary path", map[string]interface{}{"path": filepath.Join(home, "notes.txt")}, "", "open"},
		{"custom root ordinary", map[string]interface{}{"command": "date"}, custom, "open"},
		{"custom root write", map[string]interface{}{"command": "printf x >> " + customConfig}, custom, "protected"},
		{"custom root known value", map[string]interface{}{"command": `printf x >> "$DEFENSECLAW_HOME/config.yaml"`}, custom, "protected"},
		{"custom root link", map[string]interface{}{"command": "printf x >> " + customAlias}, custom, "protected"},
		{"custom root ordinary write", map[string]interface{}{"command": "printf x >> " + filepath.Join(home, "notes.txt")}, custom, "open"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			blob, err := json.Marshal(outageToolPayload{Name: "exec", Args: tc.args, CWD: home})
			if err != nil {
				t.Fatal(err)
			}
			dataDir := tc.dataDir
			if dataDir == "" {
				dataDir = filepath.Join(home, ".defenseclaw")
			}
			if got := outageToolDecision(strings.NewReader(string(blob)), dataDir); got != tc.want {
				t.Fatalf("outage decision = %q, want %q", got, tc.want)
			}
		})
	}
}
