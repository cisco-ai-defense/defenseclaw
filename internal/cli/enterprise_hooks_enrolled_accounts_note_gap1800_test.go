// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// GAP-1800 (RV-1733c P4): an enrolled-accounts record that cannot be read is
// fail-closed (every account counts as enrolled) but was silent: verify and
// Setup readiness now name it, as a warning, with what it changes and how
// to clear it. A missing or readable record adds nothing.
func TestGAP1800UnreadableEnrolledAccountsRecordIsNamed(t *testing.T) {
	gap1800TrustAll(t)
	authorizationDir := managed.HookGuardianAuthorizationDir(t.TempDir())
	if err := os.MkdirAll(authorizationDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if note := enterpriseHookEnrolledAccountsRecordProblem(authorizationDir); note != "" {
		t.Fatalf("a missing record is named: %q", note)
	}
	record := filepath.Join(authorizationDir, managed.HookGuardianEnrolledAccountsFile)
	if err := os.WriteFile(record, []byte("{\"version\":1,\"updated_at\":\"x\",\"accounts\":[\"S-1-5-21-1-2-3-1001\"]}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if note := enterpriseHookEnrolledAccountsRecordProblem(authorizationDir); note != "" {
		t.Fatalf("a readable record is named: %q", note)
	}
	if err := os.WriteFile(record, []byte("{\"version\":9,\"updated_at\":\"x\",\"accounts\":[]}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	note := enterpriseHookEnrolledAccountsRecordProblem(authorizationDir)
	for _, want := range []string{record, "unsupported version 9", "every account", "enrolled", "remove"} {
		if !strings.Contains(note, want) {
			t.Fatalf("note %q does not name %q", note, want)
		}
	}
	if enterpriseHookEnrolledAccountsRecordProblem("") != "" {
		t.Fatal("no authorization folder is named")
	}
}
