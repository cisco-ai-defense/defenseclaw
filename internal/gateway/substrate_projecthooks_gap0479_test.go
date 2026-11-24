// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// The substrate fixture (substrate_listener_test.go) is not built on Windows.

//go:build !windows

package gateway

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// GAP-0479: a hook an uploaded repository declares in .claude/settings.json
// is ignored in the actor (the managed settings set allowManagedHooksOnly),
// but nothing recorded the attempt. The kit now reports the file at
// SessionStart; the gateway writes one foreign_hook_ignored audit row per
// actor, file and content, and the hook's answer does not change. At the
// base the fact was dropped and no row was written.
func TestSubstrateProjectHooksIgnoredAreAuditedGAP0479(t *testing.T) {
	f := newSubstrateFixture(t)
	type row struct {
		sev, summary string
		details      map[string]any
	}
	var rows []row
	f.api.substrateState().audit = func(_ context.Context, sev, summary string, details map[string]any) {
		if details["event"] == "foreign_hook_ignored" {
			rows = append(rows, row{sev, summary, details})
		}
	}
	post := func(facts map[string]any) int {
		t.Helper()
		pl, _ := json.Marshal(map[string]any{"hook_event_name": "SessionStart", "session_id": "s1", "source": "startup", "cwd": "/work/app"})
		env := map[string]any{"v": substrateEnvelopeVersion, "connector": "claudecode", "event": "SessionStart",
			"mode": "interactive", "kit_version": "0.1.0", "payload": json.RawMessage(pl)}
		if facts != nil {
			env["facts"] = facts
		}
		b, _ := json.Marshal(env)
		rec := f.do(t, f.actor, http.MethodPost, "/api/v1/substrate/hook/claudecode", "tok-alice", string(b))
		return rec.Code
	}
	hooks := func(sum string) map[string]any {
		return map[string]any{"project_hooks": []map[string]any{{
			"path": "/work/app/.claude/settings.json", "sha256": sum, "events": []string{"PostToolUse", "PreToolUse"}, "hooks": 2,
		}}}
	}

	base := post(nil)
	if code := post(hooks("aa11")); code != base {
		t.Fatalf("SessionStart with ignored project hooks answered %d, without them %d: the record must not change the answer", code, base)
	}
	if len(rows) != 1 {
		t.Fatalf("%d foreign_hook_ignored rows, want 1", len(rows))
	}
	r := rows[0]
	if r.sev != "MEDIUM" || !strings.Contains(r.summary, "eng-web/alice-1") || !strings.Contains(r.summary, "/work/app/.claude/settings.json") ||
		!strings.Contains(r.summary, "PostToolUse, PreToolUse") || !strings.Contains(r.summary, "reported by the actor") {
		t.Fatalf("row %s %q", r.sev, r.summary)
	}
	if r.details["file"] != "/work/app/.claude/settings.json" || r.details["actor"] != "alice-1" || r.details["atespace"] != "eng-web" ||
		r.details["connector"] != "claudecode" || r.details["hooks"] != 2 || r.details["sha256"] != "aa11" {
		t.Fatalf("row details %v", r.details)
	}

	// Bounded: the same file and content in a later session writes no row;
	// new content (the agent added a hook) writes one more.
	post(hooks("aa11"))
	if len(rows) != 1 {
		t.Fatalf("a repeated report wrote %d rows, want 1", len(rows))
	}
	post(hooks("bb22"))
	if len(rows) != 2 {
		t.Fatalf("changed content wrote %d rows in all, want 2", len(rows))
	}
	// No project hooks, no row; a file that declares none is not one.
	post(nil)
	post(map[string]any{"project_hooks": []map[string]any{{"path": "/work/app/.claude/settings.local.json", "sha256": "cc", "hooks": 0}}})
	if len(rows) != 2 {
		t.Fatalf("%d rows after posts with no hooks, want 2", len(rows))
	}
}
