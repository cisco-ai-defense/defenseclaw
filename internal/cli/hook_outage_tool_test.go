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

func TestOpenClawOutageExecContextTargets(t *testing.T) {
	home := t.TempDir()
	old := outageAccountHome
	outageAccountHome = func() string { return home }
	t.Cleanup(func() { outageAccountHome = old })
	dataDir := filepath.Join(home, ".defenseclaw")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	protected := filepath.Join(dataDir, "config.yaml")
	if err := os.WriteFile(protected, []byte("guardrail: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	other := t.TempDir()
	for _, tc := range []struct {
		name string
		args map[string]interface{}
		want string
	}{
		{"ordinary", map[string]interface{}{"command": "date"}, "open"},
		{"unused environment path", map[string]interface{}{"command": "date", "env": map[string]interface{}{"OUT": protected}}, "open"},
		{"literal environment spelling", map[string]interface{}{"command": "printf x >> '$OUT'", "env": map[string]interface{}{"OUT": protected}}, "open"},
		{"read-only environment path", map[string]interface{}{"command": "printf '%s' \"$OUT\"", "env": map[string]interface{}{"OUT": protected}}, "open"},
		{"read environment to ordinary file", map[string]interface{}{"command": "printf '%s' \"$OUT\" > " + filepath.Join(other, "notes.txt"), "env": map[string]interface{}{"OUT": protected}}, "open"},
		{"direct", map[string]interface{}{"command": "printf x >> " + protected}, "protected"},
		{"workdir", map[string]interface{}{"command": "printf x >> config.yaml", "workdir": dataDir}, "protected"},
		{"home workdir", map[string]interface{}{"command": "printf x >> .defenseclaw/config.yaml", "workdir": "~"}, "protected"},
		{"env", map[string]interface{}{"command": "printf x >> \"$OUT\"", "env": map[string]interface{}{"OUT": protected}}, "protected"},
		{"unquoted env", map[string]interface{}{"command": "printf x >> $OUT", "env": map[string]interface{}{"OUT": protected}}, "protected"},
		{"braced env", map[string]interface{}{"command": "printf x >> \"${OUT}\"", "env": map[string]interface{}{"OUT": protected}}, "protected"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			blob, err := json.Marshal(outageToolPayload{Name: "exec", Args: tc.args, CWD: other})
			if err != nil {
				t.Fatal(err)
			}
			if got := outageToolDecision(strings.NewReader(string(blob)), dataDir); got != tc.want {
				t.Errorf("decision=%q want=%q", got, tc.want)
			}
		})
	}
}

func TestOpenClawOutageApplyPatchTarget(t *testing.T) {
	home := t.TempDir()
	old := outageAccountHome
	outageAccountHome = func() string { return home }
	t.Cleanup(func() { outageAccountHome = old })
	dataDir := filepath.Join(home, ".defenseclaw")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	protected := filepath.Join(dataDir, "config.yaml")
	if err := os.WriteFile(protected, []byte("old\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	patch := "*** Begin Patch\n*** Update File: " + protected + "\n@@\n-old\n+new\n*** End Patch"
	blob, err := json.Marshal(outageToolPayload{Name: "apply_patch", Args: map[string]interface{}{"input": patch}, CWD: home})
	if err != nil {
		t.Fatal(err)
	}
	if got := outageToolDecision(strings.NewReader(string(blob)), dataDir); got != "protected" {
		t.Errorf("apply_patch decision=%q want=protected", got)
	}
}

func TestOpenClawOutageBenignVariants(t *testing.T) {
	home := t.TempDir()
	old := outageAccountHome
	outageAccountHome = func() string { return home }
	t.Cleanup(func() { outageAccountHome = old })
	dataDir := filepath.Join(home, ".defenseclaw")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	other := t.TempDir()
	for _, tc := range []struct {
		name string
		tool string
		args map[string]interface{}
	}{
		{"date", "exec", map[string]interface{}{"command": "date"}},
		{"pwd", "exec", map[string]interface{}{"command": "pwd"}},
		{"project-write", "exec", map[string]interface{}{"command": "printf x >> notes.txt"}},
		{"home-write", "exec", map[string]interface{}{"command": "printf x >> ~/notes.txt"}},
		{"workdir-date", "exec", map[string]interface{}{"command": "date", "workdir": dataDir}},
		{"write-path", "write", map[string]interface{}{"path": filepath.Join(home, "notes.txt"), "content": "hi"}},
		{"patch", "apply_patch", map[string]interface{}{"input": "*** Begin Patch\n*** Add File: " + filepath.Join(home, "notes.txt") + "\n+hi\n*** End Patch"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			blob, err := json.Marshal(outageToolPayload{Name: tc.tool, Args: tc.args, CWD: other})
			if err != nil {
				t.Fatal(err)
			}
			if got := outageToolDecision(strings.NewReader(string(blob)), dataDir); got != "open" {
				t.Errorf("decision=%q want=open", got)
			}
		})
	}
}

func TestOpenClawOutageEnvLinkedTarget(t *testing.T) {
	home := t.TempDir()
	old := outageAccountHome
	outageAccountHome = func() string { return home }
	t.Cleanup(func() { outageAccountHome = old })
	dataDir := filepath.Join(home, ".defenseclaw")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	protected := filepath.Join(dataDir, "config.yaml")
	if err := os.WriteFile(protected, []byte("guardrail: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(home, "state-link")
	if err := os.Symlink(protected, alias); err != nil {
		t.Fatal(err)
	}
	blob, err := json.Marshal(outageToolPayload{Name: "exec", Args: map[string]interface{}{"command": "printf x >> \"$OUT\"", "env": map[string]interface{}{"OUT": alias}}, CWD: home})
	if err != nil {
		t.Fatal(err)
	}
	if got := outageToolDecision(strings.NewReader(string(blob)), dataDir); got != "protected" {
		t.Errorf("known env link decision=%q want=protected", got)
	}
}

func TestOpenClawOutageWorkdirFalseBlock(t *testing.T) {
	home := t.TempDir()
	old := outageAccountHome
	outageAccountHome = func() string { return home }
	t.Cleanup(func() { outageAccountHome = old })
	dataDir := filepath.Join(home, ".defenseclaw")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dataDir, "config.yaml"), []byte("guardrail: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	other := t.TempDir()
	blob, err := json.Marshal(outageToolPayload{Name: "exec", Args: map[string]interface{}{"command": "printf x >> config.yaml", "workdir": other}, CWD: dataDir})
	if err != nil {
		t.Fatal(err)
	}
	if got := outageToolDecision(strings.NewReader(string(blob)), dataDir); got != "open" {
		t.Errorf("ordinary workdir write decision=%q want=open", got)
	}
}
