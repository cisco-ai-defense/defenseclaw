// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package enterpriseunix

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
)

// A home_dirs entry that is the home of an account the guardian scans
// because the enumerator found it eligible is enrolled, even with no hook
// targets (every agent on machine policy); only the other folder is named
// (GAP-1092).
func TestDiscoveryHomeDirsWarningKnowsEligibleAccounts(t *testing.T) {
	h := newTestHost(t, "linux")
	writeHostFile(t, h, h.env.Layout.ConfigPath, "ai_discovery:\n  home_dirs: [/home/dcr-rs4a, /srv/eo4-shared]\n")
	writeHostFile(t, h, h.env.Layout.ManifestPath, "version: 1\ntargets: []\n")
	writeHostFile(t, h, enterprisehooks.UnixEligibleAccountsPath(h.env.Layout.ManifestPath),
		`{"version":1,"accounts":[{"user":"dcr-rs4a","uid":1001,"gid":1001,"home":"/home/dcr-rs4a"}]}`)
	l := &lifecycle{env: h.env, result: &enterprisestatus.Result{}}
	l.describeDiscoveryHomeDirs()
	got := messagesOf(l.result.Warnings, codeDiscoveryHomeDirNotEnrolled)
	if strings.Contains(got, "/home/dcr-rs4a") || !strings.Contains(got, "/srv/eo4-shared") {
		t.Fatalf("home_dirs warnings = %q, want only /srv/eo4-shared", got)
	}
}
