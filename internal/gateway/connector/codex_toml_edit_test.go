// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCodexOwnedEditPreservesUserTextAndBOM(t *testing.T) {
	before := append([]byte{0xef, 0xbb, 0xbf}, []byte(
		"# café 東京\r\nmodel = \"gpt-5\"\r\nnotify = [\"/bin/my-notify\"]\r\n# keep order\r\napproval_policy = \"on-request\"\r\n[profiles.review]\r\nmodel = \"gpt-5.1\"\r\n",
	)...)
	desired := map[string]interface{}{
		"notify": []string{"bash", "/tmp/notify-bridge.sh"},
		"hooks":  map[string]interface{}{"Stop": []string{"owned"}},
		"otel":   map[string]interface{}{"environment": "test"},
	}
	after, err := editCodexOwnedTOML(before, desired)
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range []string{"# café 東京\r\n", "model = \"gpt-5\"\r\n", "# keep order\r\n", "approval_policy = \"on-request\"\r\n", "[profiles.review]\r\n"} {
		if !bytes.Contains(after, []byte(line)) {
			t.Fatalf("user text missing after edit: %q", line)
		}
	}
	if !bytes.HasPrefix(after, before[:3]) || strings.Contains(string(after), "\r\r\n") {
		t.Fatal("Codex BOM or line endings changed")
	}
	if !(bytes.Index(after, []byte("model =")) < bytes.Index(after, []byte("notify =")) &&
		bytes.Index(after, []byte("notify =")) < bytes.Index(after, []byte("approval_policy ="))) {
		t.Fatal("the user key order changed around notify")
	}
	var decoded map[string]interface{}
	if err := parseCodexTOML(after, &decoded); err != nil {
		t.Fatalf("edited Codex TOML is invalid: %v", err)
	}
}

func TestCodexOwnedEditPreservesMultilineInstructions(t *testing.T) {
	before := []byte("developer_instructions = \"\"\"Keep this example:\nnotify = [\\\"personal\\\"]\n\"\"\"\nmodel = \"gpt-5\"\n")
	after, err := editCodexOwnedTOML(before, map[string]interface{}{"notify": []string{"owned"}})
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]interface{}
	if err := parseCodexTOML(after, &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg["developer_instructions"] != "Keep this example:\nnotify = [\"personal\"]\n" {
		t.Fatalf("instructions changed: %q", cfg["developer_instructions"])
	}
	if got, ok := cfg["notify"].([]interface{}); !ok || len(got) != 1 || got[0] != "owned" {
		t.Fatalf("root notify = %#v", cfg["notify"])
	}
}

func TestCodexOwnedEditAppendsAfterMissingFinalNewline(t *testing.T) {
	before := []byte("model = \"gpt-5\"")
	after, err := editCodexOwnedTOML(before, map[string]interface{}{"notify": []string{"owned"}})
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]interface{}
	if err := parseCodexTOML(after, &cfg); err != nil {
		t.Fatalf("invalid rendered config %q: %v", after, err)
	}
	if cfg["model"] != "gpt-5" || cfg["notify"] == nil {
		t.Fatalf("rendered config = %#v", cfg)
	}
}

func TestCodexOwnedEditIgnoresCommentBracketsInNotify(t *testing.T) {
	before := []byte("notify = [\n  \"personal\", # [ example\n]\nmodel = \"gpt-5\"\napproval_policy = \"on-request\"\n")
	after, err := editCodexOwnedTOML(before, map[string]interface{}{"notify": []string{"owned"}})
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]interface{}
	if err := parseCodexTOML(after, &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg["model"] != "gpt-5" || cfg["approval_policy"] != "on-request" {
		t.Fatalf("user settings lost: %#v", cfg)
	}
}

func TestCodexOwnedEditRecognizesCommentedTableHeader(t *testing.T) {
	before := []byte("[otel] # company telemetry\nenvironment = \"old\"\n")
	after, err := editCodexOwnedTOML(before, map[string]interface{}{"notify": []string{"owned"}, "otel": map[string]interface{}{"environment": "new"}})
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]interface{}
	if err := parseCodexTOML(after, &cfg); err != nil {
		t.Fatalf("invalid rendered config %q: %v", after, err)
	}
	if cfg["otel"].(map[string]interface{})["environment"] != "new" {
		t.Fatalf("otel = %#v", cfg["otel"])
	}
}

func TestCodexBOMReaders(t *testing.T) {
	raw := append([]byte{0xef, 0xbb, 0xbf}, []byte("# user comment\n[hooks]\ncommand = \"defenseclaw-hook\"\n[mcp_servers.demo]\ncommand = \"demo\"\n")...)
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name string
		read func() error
	}{
		{"shared parser", func() error { var doc map[string]interface{}; return ParseCodexTOML(raw, &doc) }},
		{"hook registration", func() error {
			found, err := configFileReferencesHook(path, []string{"defenseclaw-hook"})
			if err == nil && !found {
				t.Error("hook registration was not found")
			}
			return err
		}},
		{"machine requirements", func() error { _, err := parseWindowsCodexRequirements(raw); return err }},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := test.read(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
