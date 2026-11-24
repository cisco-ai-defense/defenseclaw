//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
)

// TestGAP0114AgentVersionTargetsFromVerifiedAgents: the enumerator's verified
// versions become ledger-shaped rows, one per account and connector, sorted;
// a key without a connector, an empty or invalid version, and a negative uid
// are left out.
func TestGAP0114AgentVersionTargetsFromVerifiedAgents(t *testing.T) {
	owner := func(uid int) enterprisehooks.UnixAgentOwner {
		return enterprisehooks.UnixAgentOwner{UID: uid, Home: "/home/u", HomeInode: 7}
	}
	state := &enterprisehooks.UnixEnumeratorState{VerifiedAgents: map[string]enterprisehooks.UnixVerifiedAgent{
		"dcr-std2\x00codex":      {Version: "0.168.0", Owner: owner(1002)},
		"dcr-std1\x00claudecode": {Version: "2.1.323", Owner: owner(1001)},
		"dcr-std1\x00codex":      {Version: "0.168.0", Owner: owner(1001)},
		"nokey":                  {Version: "1.0.0", Owner: owner(1003)},
		"dcr-std3\x00claudecode": {Version: "", Owner: owner(1004)},
		"dcr-neg\x00claudecode":  {Version: "2.1.323", Owner: owner(-1)},
	}}
	got := enterpriseHookAgentVersionTargets(state)
	want := []struct {
		uid                int
		connector, version string
	}{{1001, "claudecode", "2.1.323"}, {1001, "codex", "0.168.0"}, {1002, "codex", "0.168.0"}}
	if len(got) != len(want) {
		t.Fatalf("targets = %+v, want %d rows", got, len(want))
	}
	for i, w := range want {
		if got[i].UID != w.uid || got[i].Connector != w.connector || got[i].Result.AgentVersion != w.version || !got[i].OK {
			t.Errorf("row %d = %+v, want uid %d %s %s ok", i, got[i], w.uid, w.connector, w.version)
		}
	}
	if enterpriseHookAgentVersionTargets(nil) != nil {
		t.Error("nil state produced rows")
	}
}
