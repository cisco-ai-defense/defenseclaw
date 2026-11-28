// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

func activityActors(now time.Time) map[string]any {
	ago := func(d time.Duration) time.Time { return now.Add(-d) }
	return map[string]any{"actors": []map[string]any{
		{"atespace": "dev", "name": "web-3f2a", "uid": "u1", "profile": "default", "connector": "claude", "state": "running", "created_at": ago(14 * time.Minute),
			"activity": map[string]any{"state": "waiting_on_ask", "pending_asks": 1, "last": ago(41 * time.Second)}},
		{"atespace": "dev", "name": "fix-91bc", "uid": "u2", "profile": "default", "connector": "codex", "state": "running", "created_at": ago(2 * time.Hour),
			"activity": map[string]any{"state": "thinking", "pending_asks": 0, "last": ago(4 * time.Second)}},
		{"atespace": "dev", "name": "old-77aa", "uid": "u3", "profile": "default", "connector": "claude", "state": "suspended", "created_at": ago(30 * time.Hour),
			"activity": map[string]any{"state": "suspended", "pending_asks": 0, "last": time.Date(2020, 1, 2, 9, 12, 0, 0, time.UTC)}},
		{"atespace": "dev", "name": "bare", "uid": "u4", "profile": "default", "connector": "claude", "state": "running", "created_at": ago(time.Minute)},
	}}
}

// B3.6: list shows an ACTIVITY column; an agent the cluster cannot describe
// shows "-", never idle.
func TestListActivityColumn(t *testing.T) {
	f := &fakeAdmin{h: map[string]func(http.ResponseWriter, *http.Request){"GET actors": jsonReply(activityActors(time.Now()))}}
	useFakeAdmin(t, f)
	out, _, err := runSubstrate(t, newSubstrateListCmd())
	if err != nil {
		t.Fatal(err)
	}
	t.Log("\n" + out)
	for _, want := range []string{"ACTIVITY", "waiting on 1 ask", "thinking (4s ago)", "suspended since Jan 2"} {
		if !strings.Contains(out, want) {
			t.Errorf("list lacks %q:\n%s", want, out)
		}
	}
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "dev/bare") && strings.Contains(line, "idle") {
			t.Errorf("an agent without activity reads idle: %q", line)
		}
	}
	js, _, err := runSubstrate(t, newSubstrateListCmd(), "--json")
	if err != nil || !strings.Contains(js, `"activity"`) || !strings.Contains(js, `"waiting_on_ask"`) {
		t.Fatalf("--json lacks the activity object: %v %s", err, js)
	}
}

func TestStatusActivityLines(t *testing.T) {
	now := time.Now()
	one := map[string]any{"atespace": "dev", "name": "web-3f2a", "uid": "u1", "profile": "default", "connector": "claude", "state": "running", "created_at": now.Add(-14 * time.Minute),
		"activity": map[string]any{
			"state": "waiting_on_ask", "pending_asks": 1, "last": now.Add(-41 * time.Second),
			"last_model": now.Add(-41 * time.Second), "last_tool": now.Add(-43 * time.Second), "attached": now.Add(-2 * time.Minute),
			"asks": []map[string]any{{"id": "ask-1", "kind": "egress", "target": "api.stripe.com", "created": now.Add(-40 * time.Second)}},
		}}
	f := &fakeAdmin{h: map[string]func(http.ResponseWriter, *http.Request){
		"GET actors":              jsonReply(map[string]any{"actors": []map[string]any{one}}),
		"GET actors/dev/web-3f2a": jsonReply(one),
	}}
	useFakeAdmin(t, f)
	out, _, err := runSubstrate(t, newSubstrateStatusCmd(), "web-3f2a")
	if err != nil {
		t.Fatal(err)
	}
	t.Log("\n" + out)
	for _, want := range []string{
		"Activity:  waiting on an ask (1 pending: egress api.stripe.com, raised 40s ago)",
		"Last:      model call 41s ago; tool call 43s ago; you were attached 2m ago",
		"Answer:    defenseclaw substrate approvals",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("status lacks %q:\n%s", want, out)
		}
	}
}

func TestStatusActivityIdleHasNoAnswerLine(t *testing.T) {
	one := map[string]any{"atespace": "dev", "name": "web", "uid": "u1", "profile": "default", "connector": "claude", "state": "running",
		"activity": map[string]any{"state": "idle", "pending_asks": 0}}
	f := &fakeAdmin{h: map[string]func(http.ResponseWriter, *http.Request){
		"GET actors": jsonReply(map[string]any{"actors": []map[string]any{one}}), "GET actors/dev/web": jsonReply(one),
	}}
	useFakeAdmin(t, f)
	out, _, err := runSubstrate(t, newSubstrateStatusCmd(), "web")
	if err != nil || strings.Contains(out, "Answer:") || !strings.Contains(out, "Activity:  idle") || !strings.Contains(out, "Last:      -") {
		t.Fatalf("idle status: %v\n%s", err, out)
	}
}
