// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// r106PerUserVerdict sends the hook request to a per-user gateway (action
// mode) that reads the user's home itself.
func r106PerUserVerdict(t *testing.T, connector string, payload []byte, header string) string {
	t.Helper()
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = connector
	api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth()}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/hook", strings.NewReader(string(payload)))
	if header != "" {
		req.Header.Set(hookpaths.Header, header)
	}
	if connector == "codex" {
		setTestCodexHookBinding(req, "PreToolUse", defaultTestCodexHookContract)
	}
	recorder := httptest.NewRecorder()
	api.handleAgentHook(connector).ServeHTTP(recorder, req)
	body := recorder.Body.String()
	switch {
	case strings.HasPrefix(body, `{"action":"block"`):
		return "block"
	case strings.HasPrefix(body, `{"action":"allow"`):
		return "allow"
	}
	return fmt.Sprintf("status %d body %.200s", recorder.Code, body)
}

// r106Verdicts returns the per-user and the managed (ProtectHome) verdicts
// of one command in a fresh fixture, with the real hook client's header.
func r106Verdicts(t *testing.T, connector, command string) (perUser, managed string) {
	t.Helper()
	f := newB36ManagedHookFixture(t)
	for _, name := range []string{"notes.txt", "README.md"} {
		if err := os.WriteFile(filepath.Join(f.project, name), []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink("README.md", filepath.Join(f.project, "readlink")); err != nil {
		t.Fatal(err)
	}
	payload := f.payload(t, command)
	header := f.clientHeader(t, payload)
	perUser = r106PerUserVerdict(t, connector, payload, header)
	managed = f.post(t, connector, payload, header)
	if err := os.Chmod(f.homes, 0o700); err != nil {
		t.Fatal(err)
	}
	return perUser, managed
}

// TestR106CommentNamingKeysIsNotAKeysWrite (rel-1-0-6:GAP-0133): an echo
// whose trailing shell comment only names the authorized-keys path is
// allowed in action mode, per-user and managed, Claude Code and Codex;
// real writes to the keys file next to a comment still block.
func TestR106CommentNamingKeysIsNotAKeysWrite(t *testing.T) {
	for _, tc := range []struct {
		command string
		want    string
	}{
		{"echo done # see ~/.ssh/authorized_keys later", "allow"},
		{"echo done >> notes.txt # see ~/.ssh/authorized_keys later", "allow"},
		{"echo a > notes.txt\n# then ~/.ssh/authorized_keys\necho b >> notes.txt", "allow"},
		{"echo x >> ~/.ssh/authorized_keys # note", "block"},
		{"echo x >> \"$HOME/.ssh/authorized_keys\" # note", "block"},
		{"bash -c \"echo x >> ~/.ssh/authorized_keys\" # note", "block"},
		{"echo x >> keylink # note", "block"},
		{"echo \"# note\" >> ~/.ssh/authorized_keys", "block"},
		{"echo ok # c\necho x >> ~/.ssh/authorized_keys", "block"},
	} {
		for _, connector := range []string{"claudecode", "codex"} {
			perUser, managed := r106Verdicts(t, connector, tc.command)
			if perUser != tc.want || managed != tc.want {
				t.Errorf("%s %q: per-user %s, managed %s, want %s", connector, tc.command, perUser, managed, tc.want)
			}
		}
	}
}
