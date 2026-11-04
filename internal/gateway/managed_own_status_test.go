// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// cowork-1-0-8 GAP-0053: a standard user of a managed computer reads their
// own Claude Code and Cowork protection state on the hook socket. The answer
// is the kernel-verified caller's: another account's last Cowork event, the
// administrator's profiles and paths are never in it.
func TestOwnStatusAnswersOnlyTheCaller(t *testing.T) {
	previous := ownStatusCoworkEvents
	t.Cleanup(func() { ownStatusCoworkEvents = previous })
	mine := time.Date(2026, 11, 4, 9, 0, 0, 0, time.UTC)
	var readPath string
	ownStatusCoworkEvents = func(_ context.Context, path string) ([]enterprisestatus.CoworkAccountEvent, bool, error) {
		readPath = path
		return []enterprisestatus.CoworkAccountEvent{
			{UserID: "5002", UserName: "bob", At: mine.Add(time.Hour)},
			{UserID: "5001", UserName: "alice", At: mine},
			{UserName: "carol", At: mine.Add(2 * time.Hour)},
		}, false, nil
	}
	status := func(api *APIServer, peer *managedHookPeer) (int, string, map[string]any) {
		req := httptest.NewRequest(http.MethodGet, managed.OwnStatusPath, nil)
		if peer != nil {
			req = req.WithContext(withManagedHookPeer(req.Context(), *peer))
		}
		rec := httptest.NewRecorder()
		api.handleOwnStatus(rec, req)
		var out map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return rec.Code, rec.Body.String(), out
	}
	cfg := &config.Config{AuditDB: "/var/lib/defenseclaw/audit.db"}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "claudecode"
	cfg.Guardrail.Profiles = map[string]config.GuardrailProfile{"secret-admin-profile": {Mode: "observe"}}
	api := NewAPIServer("127.0.0.1:0", nil, nil, nil, nil, cfg)
	alice := &managedHookPeer{UID: 5001, Name: "alice"}
	code, body, out := status(api, alice)
	cowork, _ := out["cowork"].(map[string]any)
	claude, _ := out["claude_code"].(map[string]any)
	if code != http.StatusOK || out["own"] != true || out["managed_by"] != "your organization" ||
		cowork["protected"] != true || claude["protected"] != true || cowork["last_event_at"] != mine.Format(time.RFC3339) {
		t.Fatalf("own status = %d %s; want alice's protected state and her own last Cowork event", code, body)
	}
	if readPath != cfg.AuditDB {
		t.Fatalf("read the audit store at %q, want %q", readPath, cfg.AuditDB)
	}
	for _, leak := range []string{"bob", "5002", "carol", "secret-admin-profile", "audit.db", "profiles", "enrolled"} {
		if strings.Contains(body, leak) {
			t.Fatalf("own status names %q: %s", leak, body)
		}
	}
	// An account with no Cowork event of its own gets none, not another
	// account's; a row without a user id counts only for its own name.
	if _, body, out := status(api, &managedHookPeer{UID: 5003, Name: "carol"}); !strings.Contains(body, mine.Add(2*time.Hour).Format(time.RFC3339)) {
		t.Fatalf("carol's own name-only row is missing: %s", body)
	} else if out["cowork"].(map[string]any)["protected"] != true {
		t.Fatalf("carol = %s", body)
	}
	if _, body, _ := status(api, &managedHookPeer{UID: 5004, Name: "dave"}); strings.Contains(body, "last_event_at") {
		t.Fatalf("dave sees someone else's Cowork event: %s", body)
	}
	if code, _, _ := status(api, nil); code != http.StatusForbidden {
		t.Fatalf("own status without a verified peer = %d; want 403", code)
	}

	off := &config.Config{}
	off.Guardrail.Mode = "action"
	off.Guardrail.Connector = "codex"
	_, body, out = status(NewAPIServer("127.0.0.1:0", nil, nil, nil, nil, off), alice)
	if out["cowork"].(map[string]any)["protected"] != false || out["claude_code"].(map[string]any)["protected"] != false {
		t.Fatalf("own status without the Claude Code connector = %s; want not protected", body)
	}
}
