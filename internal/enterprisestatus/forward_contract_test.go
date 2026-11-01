// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package enterprisestatus

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/contracttest"
)

// A lifecycle result that names sessions to restart forwards their count
// and connector names (enforcement_pending, bundle.sessions_restart_required
// count and state), never the account, pid or start time of an entry
// (sidecar-r107 GAP-0006).
func TestForwardLifecycleResultSessionsKeepAccountsOnTheDevice(t *testing.T) {
	schemas := contracttest.Compile(t)
	r := New("status", "standalone", "linux", "")
	r.Installed, r.InstalledVersion = true, "1.0.7"
	r.Bundle = &BundleState{BundleID: "b-01JA0000000000000000000002", Version: 8, State: BundleFailed,
		ErrorCode: "signature_invalid", CurrentBundleID: "b-01JA0000000000000000000001", CurrentVersion: 7,
		SessionsRestartRequired: &SessionRestartStatus{State: "known", Count: 23, Entries: []SessionEntry{
			{PID: 4242, User: "dcad-alice", Agent: "claudecode", StartedAt: "2026-11-01T01:00:00Z"},
			{PID: 4343, User: "1104", Agent: "codex", StartedAt: "2026-11-01T01:05:00Z"},
		}}}
	r.NotePendingSession("cursor", 5151)
	r.Finish("linux", 0)

	doc := schemas.ValidateValue(t, lifecycleSchema, r)
	if doc["enforcement_pending"] == nil {
		t.Fatalf("the result names no enforcement_pending: %v", doc)
	}
	projected, _ := schemas.Project(t, "lifecycle-result-forward.schema.json", doc)
	text, err := json.Marshal(projected)
	if err != nil {
		t.Fatal(err)
	}
	pending, _ := json.Marshal(projected["enforcement_pending"])
	sessions, _ := json.Marshal(projected["bundle"].(map[string]any)["sessions_restart_required"])
	if string(pending) != `{"connectors":["claudecode","codex","cursor"],"count":24}` ||
		string(sessions) != `{"count":23,"state":"known"}` {
		t.Fatalf("forwarded enforcement_pending %s, bundle.sessions_restart_required %s", pending, sessions)
	}
	for _, local := range []string{"dcad-alice", "1104", "4242", "5151", `"entries"`, `"user"`, `"pid"`, "started_at"} {
		if strings.Contains(string(text), local) {
			t.Errorf("the projection forwards %s: %s", local, text)
		}
	}
}
