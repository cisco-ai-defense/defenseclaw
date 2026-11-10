// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package watcher

import (
	"context"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// A server whose launcher the scanner refused stays blocked and disabled. The
// entry is then replaced by another definition under the same name, which is
// refused as well, and an administrator allows that exact replacement: the
// allow admits it without a scan and the block of the earlier refusal, which
// the name carried into the next session, is released.
func TestExactAllowOfARefusedReplacementReleasesTheBlockForTheName(t *testing.T) {
	h, scan, _ := refusedNodeHarness(t)
	server := &h.servers[0]
	server.Args = []string{"/home/u/proj/time-server.js", "2"}
	if got := h.poll(); len(got) != 1 || got[0].Verdict != VerdictBlocked {
		t.Fatalf("admission of the replacement %+v, want a fail-closed block", got)
	}
	if state := h.journal(*server); state.Runtime != "disable" || state.Install != "block" {
		t.Fatalf("journal %+v, want the refused replacement blocked and disabled", state)
	}
	h.w.cfg.AssetPolicy.MCP.Allowed = []config.AssetPolicyRule{{Name: server.Name, Command: server.Command, ArgsPrefix: server.Args, Reason: "reviewed"}}
	scans := scan.count()
	// What a hook call and the discovery poll do once the allow is written;
	// the periodic rescan is not waited for.
	h.pending(*server)
	h.poll()
	if scan.count() != scans {
		t.Fatalf("the allowed replacement was scanned %d times", scan.count()-scans)
	}
	if state := h.journal(*server); !state.IsEmpty() {
		t.Fatalf("the allowed replacement is still refused for the name: %+v", state)
	}
}

// Benign twin: an allow of another definition leaves the refusal of the
// listed one in place.
func TestAllowOfAnotherDefinitionLeavesTheRefusedReplacementBlocked(t *testing.T) {
	h, _, _ := refusedNodeHarness(t)
	server := &h.servers[0]
	server.Args = []string{"/home/u/proj/time-server.js", "2"}
	if got := h.poll(); len(got) != 1 || got[0].Verdict != VerdictBlocked {
		t.Fatalf("admission of the replacement %+v, want a fail-closed block", got)
	}
	evt := InstallEvent{Type: InstallMCP, Name: server.Name, Path: MCPEventPath(*server), Connector: server.Connector}
	h.w.cfg.AssetPolicy.MCP.Allowed = []config.AssetPolicyRule{{Name: server.Name, Command: server.Command, ArgsPrefix: []string{"/home/u/proj/time-server.js", "3"}}}
	h.w.rescanTarget(context.Background(), evt, nil)
	if state := h.journal(*server); state.Runtime != "disable" || state.Install != "block" {
		t.Fatalf("journal %+v, want the replacement still blocked", state)
	}
}
