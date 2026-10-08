// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/acp"
	"github.com/defenseclaw/defenseclaw/internal/config"
)

// A revoke of a signed-out Windows user records the user's copy, and the
// enumerator removes it once the user is signed in (GAP-0718).
func TestEnterpriseACPUserCopyRemovedAtNextSignIn(t *testing.T) {
	previousCfg := cfg
	t.Cleanup(func() { cfg = previousCfg })
	cfg = &config.Config{DataDir: t.TempDir(), DeploymentMode: "managed_enterprise"}
	enrollment := enterpriseACPEnrollment{
		target:    enterpriseHookTarget{home: `C:\Users\dcw-w2a1`, uid: -1, gid: -1, sid: "S-1-5-21-1-2-3-1001"},
		principal: "sid:S-1-5-21-1-2-3-1001", client: "zed", agent: "kiro", profile: "w2w-obs",
	}
	note := enterpriseACPDeferUserCopyCleanup(enrollment, `C:\Users\dcw-w2a1\.defenseclaw\acp\zed-kiro.token`)
	if !strings.Contains(note, "until the next sign-in") || strings.Contains(note, "enroll") {
		t.Fatalf("note = %q", note)
	}
	signedIn := false
	remove := func(entry acp.EnterpriseUserCopyCleanup) (bool, error) { return signedIn, nil }
	var log bytes.Buffer
	cleanEnterpriseACPUserCopies(cfg.DataDir, remove, nil, &log)
	if pending, _ := acp.EnterpriseUserCopyCleanups(cfg.DataDir); len(pending) != 1 {
		t.Fatalf("pending while signed out = %v", pending)
	}
	signedIn = true
	cleanEnterpriseACPUserCopies(cfg.DataDir, remove, nil, &log)
	if pending, _ := acp.EnterpriseUserCopyCleanups(cfg.DataDir); len(pending) != 0 || !strings.Contains(log.String(), "removed the revoked ACP token copy") {
		t.Fatalf("pending after sign-in = %v, log = %q", pending, log.String())
	}
}

// The Windows enumerator revokes the enrollments of a deleted account and
// keeps every other one (GAP-0367).
func TestRevokeEnterpriseACPEnrollmentsOfDeletedSIDs(t *testing.T) {
	dataDir := t.TempDir()
	const gone, present = "S-1-5-21-1-2-3-1117", "S-1-5-21-1-2-3-1118"
	for _, principal := range []string{"sid:" + gone, "sid:" + present, "uid:1117"} {
		if _, err := acp.EnsureEnterpriseCredential(dataDir, principal, "zed", "hermes", "w2w-obs"); err != nil {
			t.Fatal(err)
		}
	}
	var log bytes.Buffer
	revoked := revokeEnterpriseACPEnrollmentsOfDeletedSIDs(dataDir, func(sid string) bool { return sid == gone }, &log)
	if len(revoked) != 1 || !strings.Contains(revoked[0], gone) || !strings.Contains(log.String(), "revoked its ACP enrollment") {
		t.Fatalf("revoked = %v, log = %q", revoked, log.String())
	}
	if _, err := acp.LoadEnterpriseCredential(dataDir, "sid:"+gone, "zed", "hermes", "w2w-obs"); !os.IsNotExist(err) {
		t.Fatalf("the deleted account kept its credential: %v", err)
	}
	for _, principal := range []string{"sid:" + present, "uid:1117"} {
		if _, err := acp.LoadEnterpriseCredential(dataDir, principal, "zed", "hermes", "w2w-obs"); err != nil {
			t.Fatalf("%s lost its credential: %v", principal, err)
		}
	}
}
