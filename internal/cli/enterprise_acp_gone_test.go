// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/acp"
)

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
