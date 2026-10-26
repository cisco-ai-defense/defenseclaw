// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Codex's TUI may reuse an app server launched before a shell export. The
// operator guide must use persisted config for its closed posture, rather
// than promise that an ambient strictness flag reaches the hook (GAP-0782).
func TestFailModeGuideUsesPersistentConfigForCodexTUI(t *testing.T) {
	path := filepath.Join("..", "..", "..", "docs-site", "content", "docs", "reference", "fail-modes.mdx")
	guide, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(guide)
	if strings.Contains(text, "DEFENSECLAW_STRICT_AVAILABILITY") {
		t.Fatal("fail-mode guide still promises a process flag as operational policy")
	}
	if !strings.Contains(text, "Codex TUI") || !strings.Contains(text, "guardrail.hook_fail_mode: closed") {
		t.Fatal("fail-mode guide does not point Codex TUI operators to persisted config")
	}
}

func TestFailModeGuideHonorsExplicitSavedOSSOutageMode(t *testing.T) {
	path := filepath.Join("..", "..", "..", "docs-site", "content", "docs", "reference", "configuration", "fail-modes.mdx")
	guide, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(guide)
	for _, stale := range []string{
		"a saved `guardrail.hook_fail_mode` does not change a per-user hook",
		"A per-user install ignores a saved value",
		"Per-user: not read",
		"only on the standalone enterprise profile",
	} {
		if strings.Contains(text, stale) {
			t.Errorf("outdated saved-mode claim: %s", stale)
		}
	}
	if !strings.Contains(text, "An explicit saved `closed` or `open` wins over the policy tier") {
		t.Fatal("guide does not explain the saved OSS outage mode")
	}
}
