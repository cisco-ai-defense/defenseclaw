// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package watcher

import (
	"testing"
)

// A hook-stated refusal of the listed definition is a failed admission like
// any other, so a revoked earlier definition the agent may still run is the
// more restrictive verdict and comes first: an allow written for the listed
// one cannot answer it (GAP-0920, GAP-0925). With the earlier allow standing,
// the refusal is the listed definition own, unmarked.
func TestRevokedEarlierDefinitionWinsOverARefusedListedReplacement(t *testing.T) {
	f := newRemovableEntryFixture(t)
	original := f.server
	f.admittedByAllowRule()
	f.server.URL = ""
	f.server.Command = "python3"
	f.server.Args = []string{"server.py"}
	f.server.LocalRefusal = "launcher"
	query := MCPAdmissionQuery{Connector: original.Connector, Server: original.Name, Home: original.Home}
	if status := f.w.MCPAdmissionStatus(query); !status.Failed || status.Revoked || status.ScanIssue != MCPScanIssueLauncher {
		t.Fatalf("the refused replacement with the first allow standing: %+v, want its own refusal, not revoked", status)
	}
	f.cfg.AssetPolicy.MCP.Allowed = nil
	if status := f.w.MCPAdmissionStatus(query); !status.Failed || !status.Revoked {
		t.Fatalf("the refused replacement with the first allow revoked: %+v, want the revoked admission of the earlier definition", status)
	}
}
