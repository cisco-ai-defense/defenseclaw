// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package relay

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/defenseclaw/defenseclaw/internal/substrate/kit"
)

// GAP-0120: the agent owns HOME, so it can rename Antigravity's root-owned
// ~/.gemini away and make its own hooks file in a new one. The relay sees
// the folder move, stops the agent and its session, says why on the
// terminal, and refuses every new attachment.
func TestGuardStopsTheAgentWhenItsHookFolderMoves(t *testing.T) {
	gem := filepath.Join(t.TempDir(), ".gemini")
	if err := os.Mkdir(gem, 0o755); err != nil {
		t.Fatal(err)
	}
	s, _, ec := testServer(t, []string{"sh", "-c", "while read l; do echo got:$l; done"})
	s.opts.Guard = []string{gem}
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()
	c, _, err := dialWS(t, srv.URL, ec.token(t, claims(time.Now(), nil), TokenType), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.WriteMessage(websocket.BinaryMessage, Encode(FrameData, []byte("one\r")))
	readUntil(t, c, "got:one", nil)

	// A benign change in the folder is nothing.
	if err := os.WriteFile(filepath.Join(gem, "state.json"), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	time.Sleep(300 * time.Millisecond)
	if !s.agent.Running() {
		t.Fatal("a write inside the guarded folder stopped the agent")
	}

	if err := os.Rename(gem, gem+".x"); err != nil {
		t.Fatal(err)
	}
	_ = os.MkdirAll(filepath.Join(gem, "config"), 0o755)
	out := readUntil(t, c, "hook folder", nil)
	if !strings.Contains(out, "was moved") {
		t.Fatalf("the terminal did not say why: %q", out)
	}
	deadline := time.Now().Add(5 * time.Second)
	for s.agent.Running() && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if s.agent.Running() {
		t.Fatal("the agent kept running after its hook folder moved")
	}
	if _, resp, err := dialWS(t, srv.URL, ec.token(t, claims(time.Now(), nil), TokenType), nil); err == nil || resp.StatusCode != 403 {
		t.Fatalf("an attachment after the move: %v", err)
	}
}

// The guard watches only Antigravity's folder, and a missing folder at
// start refuses the agent (its start wrapper would refuse it too).
func TestGuardedDirsAndMissingFolder(t *testing.T) {
	if got := kit.GuardedDirs("antigravity", "/sandbox"); len(got) != 1 || got[0] != "/sandbox/.gemini" {
		t.Fatalf("antigravity: %v", got)
	}
	for _, c := range []string{"claudecode", "codex", "devin", "cursor", "kiro", "amp", "opencode", "copilot", "hermes"} {
		if got := kit.GuardedDirs(c, "/sandbox"); got != nil {
			t.Errorf("%s: %v", c, got)
		}
	}
	s, _, _ := testServer(t, []string{"sh"})
	s.opts.Guard = []string{filepath.Join(t.TempDir(), "missing")}
	if err := s.init(); err == nil || !strings.Contains(err.Error(), "hook folder is not in place") {
		t.Fatalf("init with the guarded folder missing: %v", err)
	}
}
