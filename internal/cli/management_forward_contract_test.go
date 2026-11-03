// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/contracttest"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
)

// TestManagementContractForwardBundleStatusSessions: bundle status with
// sessions to restart validates, and its projection through
// forward/bundle-status-forward.schema.json keeps the count, the state and
// the connector names (enforcement_pending) and drops the entries, which
// name accounts (sidecar-r107 GAP-0006: the guide told the agent to forward
// entries[].agent, which the forward schema dropped).
func TestManagementContractForwardBundleStatusSessions(t *testing.T) {
	schemas := contracttest.Compile(t)
	e := newBundleCLIEnv(t)
	e.writeAnchors(t, map[string]any{"k1": e.edKey.Public()})
	store := bundleDevice(t, e)
	digest := "sha256:" + strings.Repeat("7", 64)
	confirmBundleDelivery(t, store, "b-01JA0000000000000000000007", 7, digest, "agent-7:d.7")
	bundleGatewayPolicy = func(context.Context) *enterprisestatus.PolicyState {
		return &enterprisestatus.PolicyState{EffectiveDigest: digest, GatewayReportedDigest: digest, Applied: true}
	}
	bundleSessionStatus = func(context.Context) enterprisestatus.SessionRestartStatus {
		return enterprisestatus.SessionRestartStatus{State: "known", Count: 21, Entries: []enterprisestatus.SessionEntry{
			{PID: 4242, User: "dcad-alice", Agent: "claudecode", StartedAt: "2026-11-01T01:00:00Z"},
			{PID: 4343, User: "1104", Agent: "codex", StartedAt: "2026-11-01T01:05:00Z"},
		}}
	}

	out, code := runBundle(t, "status", "--json")
	doc := schemas.Validate(t, "bundle-status.schema.json", []byte(out))
	requireExit(t, doc, code, 0)
	projected, _ := schemas.Project(t, "bundle-status-forward.schema.json", doc)
	text, err := json.Marshal(projected)
	if err != nil {
		t.Fatal(err)
	}
	for member, want := range map[string]string{
		"enforcement_pending":       `{"connectors":["claudecode","codex"],"count":21}`,
		"sessions_restart_required": `{"count":21,"state":"known"}`,
	} {
		if got, _ := json.Marshal(projected[member]); string(got) != want {
			t.Errorf("forwarded %s = %s, want %s", member, got, want)
		}
	}
	if got, _ := json.Marshal(projected["bundle"].(map[string]any)["sessions_restart_required"]); string(got) != `{"count":21,"state":"known"}` {
		t.Errorf("forwarded bundle.sessions_restart_required = %s", got)
	}
	for _, local := range []string{"dcad-alice", "1104", "4242", `"entries"`, `"user"`, `"pid"`, "started_at", `"message"`} {
		if strings.Contains(string(text), local) {
			t.Errorf("the projection forwards %s: %s", local, text)
		}
	}
}
