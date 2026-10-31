// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"bytes"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/inventory"
)

// rel-1-0-2 GAP-0618: an agent started as another account in a signed-in
// session is counted for its own account, not the session account.
func TestEnterpriseWindowsEnumerateRunningAgentsCountsARunasAgentForItsAccount(t *testing.T) {
	const session, runas = "S-1-5-21-1-2-3-1001", "S-1-5-21-1-2-3-1002"
	stubEnumerateRunningAgents(t, []inventory.AgentProcess{
		{PID: 50, Connector: "codex", User: `DCLAB\bob`, OwnerSID: session, OwnerSIDFromSession: true},
	}, nil, map[string]string{`DCLAB\bob`: runas})
	got, unknown := enterpriseWindowsEnumerateRunningAgents(new(bytes.Buffer), []string{"codex"}, "")
	if got[runas]["codex"] != "codex (pid 50)" || got[session] != nil || len(unknown) != 0 {
		t.Fatalf("runas agent: rows %+v, unknown %+v", got, unknown)
	}
}
