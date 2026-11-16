// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enforce"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
)

// A quarantine removal the hook guardian deferred until the owner signs in
// is a status and verify warning that names the folder left in the user's
// profile and why the guardian waits; one whose folder is gone is not
// reported (p0-round GAP-0797, GAP-0795).
func TestDeferredQuarantineRemovalIsAStatusWarningWithTheReason(t *testing.T) {
	dataDir, guardian := t.TempDir(), t.TempDir()
	present := filepath.Join(t.TempDir(), "Users", "dcad-pw2", ".claude", "skills", "epa-crit-c")
	if err := os.MkdirAll(present, 0o700); err != nil {
		t.Fatal(err)
	}
	reason := "the owner of dcad-pw2 is signed out, and Windows refused an S4U logon for this Active Directory account of domain DCLAB " +
		"(Kerberos, through a domain controller); the guardian removes the folder when that user next signs in"
	channel := enforce.QuarantineRemovalChannelFor(dataDir, guardian)
	if err := os.MkdirAll(channel.DeferredDir, 0o700); err != nil {
		t.Fatal(err)
	}
	for id, source := range map[string]string{"q-present": present, "q-gone": filepath.Join(t.TempDir(), "gone")} {
		raw, _ := json.Marshal(enforce.QuarantineRemovalRequest{Version: 1, ID: id, TargetType: "skill", SourcePath: source, Deferred: reason})
		if err := os.WriteFile(filepath.Join(channel.DeferredDir, id+".json"), raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	result := &enterprisestatus.Result{}
	appendAdmissionIssueWarnings(result, dataDir, guardian)
	if len(result.Warnings) != 1 || result.Warnings[0].Code != "asset_removal_deferred" {
		t.Fatalf("warnings %+v", result.Warnings)
	}
	message := result.Warnings[0].Message
	if !strings.Contains(message, "the skill "+present+" is in quarantine and blocked, but its original folder stays") ||
		!strings.Contains(message, "dcad-pw2 is signed out") || !strings.Contains(message, "Active Directory account of domain DCLAB") {
		t.Fatalf("the deferred removal warning lacks the folder or the reason: %s", message)
	}
}
