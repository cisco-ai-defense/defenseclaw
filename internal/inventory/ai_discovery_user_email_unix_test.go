// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package inventory

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A per-user scan reads the user's own connector address, and names a
// connector file it cannot use (here a .codex that links into another
// account's home) instead of taking that account's address (GAP-0961).
func TestUserScanReadsOnlyTheOwnersConnectorEmail(t *testing.T) {
	home, other := t.TempDir(), t.TempDir()
	if err := os.WriteFile(filepath.Join(home, ".claude.json"), []byte(`{"oauthAccount":{"emailAddress":"rs4a@example.test"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	// Payload {"email":"other@example.test"}; the signature is not checked.
	token := "e30.eyJlbWFpbCI6Im90aGVyQGV4YW1wbGUudGVzdCJ9.c2ln"
	if err := os.MkdirAll(filepath.Join(other, ".codex"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(other, ".codex", "auth.json"), []byte(`{"tokens":{"id_token":"`+token+`"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(other, ".codex"), filepath.Join(home, ".codex")); err != nil {
		t.Fatal(err)
	}
	svc := &ContinuousDiscoveryService{opts: AIDiscoveryOptions{IncludeUserEmail: true}, userHomeScan: true}
	signals := []AISignal{{SupportedConnector: "claudecode"}, {SupportedConnector: "codex"}}
	svc.stampConnectorEmails(signals, func(AISignal) string { return home })
	if signals[0].UserEmail != "rs4a@example.test" || signals[1].UserEmail != "" {
		t.Fatalf("emails = %q / %q, want the user's own Claude Code address only", signals[0].UserEmail, signals[1].UserEmail)
	}
	if note := svc.emailNotes["user_email:codex"]; !strings.Contains(note, "outside the profile") {
		t.Fatalf("codex note = %q, want a named warning", note)
	}
}
