// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

// Package connectortest is a test-only helper package that lives
// outside the connector package's production import graph. It
// provides ergonomic fixture builders for ZeptoClaw, Claude Code,
// and Codex test setups so non-OpenClaw test parity (plan E5) does
// not litter individual *_test.go files with duplicated home-dir
// scaffolding and config marshalling.
//
// All helpers honor t.TempDir() and t.Cleanup() so a failing test
// never leaves stray files. Helpers return the synthetic HOME so
// the caller can then set HOME or a connector's *HomeOverride
// global before calling Setup().
package connectortest

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// WithTempHome returns a temporary directory rooted at t.TempDir()
// and registers a cleanup to remove it. The returned path is
// suitable for use as $HOME or a per-connector HomeOverride.
//
// Note: callers are responsible for setting the env var or override
// themselves — the helper only owns the directory's lifecycle.
func WithTempHome(t *testing.T) string {
	t.Helper()
	return t.TempDir()
}

// ZeptoClawProviderEntry is the structural shape that
// SeedZeptoClawConfig writes under “providers.<name>“. We keep
// our own struct here (rather than importing connector.ZeptoClawProviderEntry)
// so this package never gains a production dependency on connector.
type ZeptoClawProviderEntry struct {
	APIBase string `json:"api_base"`
	APIKey  string `json:"api_key"`
}

// SeedZeptoClawConfig writes a minimal ~/.zeptoclaw/config.json
// blob populated with the given providers. Returns the absolute
// path to the file so callers can assert on it.
func SeedZeptoClawConfig(t *testing.T, home string, providers map[string]ZeptoClawProviderEntry) string {
	t.Helper()
	dir := filepath.Join(home, ".zeptoclaw")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir zeptoclaw home: %v", err)
	}
	body := map[string]any{
		"providers": providers,
		"safety": map[string]any{
			"allow_private_endpoints": false,
		},
	}
	return writeJSON(t, filepath.Join(dir, "config.json"), body)
}

// ClaudeCodeHookRule mirrors the structural “hooks[]“ entry shape
// that Claude Code reads from settings.json. Used by
// SeedClaudeCodeSettings to populate the “hooks“ array without
// requiring importers to know the upstream schema details.
type ClaudeCodeHookRule struct {
	Event   string `json:"event"`
	Matcher string `json:"matcher,omitempty"`
	Command string `json:"command"`
}

// SeedClaudeCodeSettings writes a ~/.claude/settings.json blob with
// the requested hooks + mcpServers entries. Returns the absolute
// path to the file.
func SeedClaudeCodeSettings(t *testing.T, home string, hooks []ClaudeCodeHookRule, mcps map[string]any) string {
	t.Helper()
	dir := filepath.Join(home, ".claude")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir claude home: %v", err)
	}
	body := map[string]any{
		"hooks":      hooks,
		"mcpServers": mcps,
	}
	return writeJSON(t, filepath.Join(dir, "settings.json"), body)
}

// SeedCodexConfig writes a minimal ~/.codex/config.toml blob.
// Codex's config is TOML; we emit a small, hand-formed string
// rather than pulling in a TOML marshal dependency just for tests
// — keeping our test-helper deps slim avoids tripping the
// supply-chain rule against transitive test imports.
func SeedCodexConfig(t *testing.T, home string, hooksBlock string, modelProvider string) string {
	t.Helper()
	dir := filepath.Join(home, ".codex")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir codex home: %v", err)
	}
	path := filepath.Join(dir, "config.toml")
	body := ""
	if modelProvider != "" {
		body += "model = \"" + modelProvider + "\"\n"
	}
	if hooksBlock != "" {
		body += hooksBlock + "\n"
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("write codex config: %v", err)
	}
	return path
}

// SeedSkillDir creates a “<home>/<connectorRel>/skills/<name>“
// directory with a minimal SKILL.md so connector skill enumeration
// finds it.
func SeedSkillDir(t *testing.T, home, connectorRel, name string) string {
	t.Helper()
	dir := filepath.Join(home, connectorRel, "skills", name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir skill: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte("# "+name+"\n"), 0o644); err != nil {
		t.Fatalf("write SKILL.md: %v", err)
	}
	return dir
}

// SeedPluginDir creates a host plugin dir at
// “<home>/<connectorRel>/plugins/<name>“ with a manifest stub.
// Manifest format ('plugin.json' or 'package.json') drives the
// matrix tests in C6.
func SeedPluginDir(t *testing.T, home, connectorRel, name, manifestName string, manifest map[string]any) string {
	t.Helper()
	dir := filepath.Join(home, connectorRel, "plugins", name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir plugin: %v", err)
	}
	writeJSON(t, filepath.Join(dir, manifestName), manifest)
	return dir
}

func writeJSON(t *testing.T, path string, body any) string {
	t.Helper()
	data, err := json.MarshalIndent(body, "", "  ")
	if err != nil {
		t.Fatalf("marshal %s: %v", path, err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return path
}
