// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package watcher

import "testing"

// GAP-0203: the install-allowed audit row says why admission allowed an asset
// before any scan. scan_on_install: false is not an allow-list entry. The
// Secure Client deployment keeps the old label.
func TestAllowedAuditReason(t *testing.T) {
	cfg, store, logger, skillDir := setupTestEnv(t)
	w := New(cfg, []string{skillDir}, nil, store, logger, nil, nil)
	cases := map[string]string{
		"scan_on_install disabled — allowed without scan": "scan-disabled",
		"mcp 'x' is on the allow list — scan skipped":     "allow-listed",
		"": "allow-listed",
	}
	for in, want := range cases {
		if got := w.allowedAuditReason(in); got != want {
			t.Errorf("allowedAuditReason(%q) = %q, want %q", in, got, want)
		}
	}

	sc := *cfg
	sc.DeploymentMode = "managed_enterprise"
	sc.Enterprise.Profile = "secure_client"
	wsc := New(&sc, []string{skillDir}, nil, store, logger, nil, nil)
	if got := wsc.allowedAuditReason("scan_on_install disabled — allowed without scan"); got != "allow-listed" {
		t.Errorf("Secure Client label = %q, want the unchanged allow-listed", got)
	}
}
