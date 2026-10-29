//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/acp"
	"github.com/defenseclaw/defenseclaw/internal/config"
)

// An enrollment made with --user-home alone records a digest of the home.
// List named its account, token copy and setup unknown while verify said the
// user had run setup (GAP-2431, managed macOS pod observation).
func TestEnterpriseACPListDescribesAHomeEnrollmentByItsRecordedDataDir(t *testing.T) {
	home := t.TempDir()
	userData := filepath.Join(home, "acp-data")
	if _, err := acp.PublishEnterpriseUserToken(userData, "zed", "kiro", strings.Repeat("ab", 32)); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(filepath.Clean(home)))
	principal := "home:" + hex.EncodeToString(sum[:])
	owner := fmt.Sprintf("uid:%d", os.Getuid())
	restoreCfg := cfg
	t.Cleanup(func() { cfg = restoreCfg })
	cfg = &config.Config{ACP: config.ACPConfig{Enabled: true}}
	restore := enterpriseACPDescribePrincipal
	t.Cleanup(func() { enterpriseACPDescribePrincipal = restore })
	enterpriseACPDescribePrincipal = func(p string) (enterpriseACPAccount, error) {
		if p != owner {
			return enterpriseACPAccount{}, fmt.Errorf("%s names no account", p)
		}
		return enterpriseACPAccount{exists: true, name: "alice", home: "/elsewhere", uid: -1, gid: -1}, nil
	}

	row := describeEnterpriseACPEnrollment(acp.EnterpriseEnrollment{
		Principal: principal, ClientID: "zed", AgentID: "kiro", Profile: "locked", UserDataDir: userData,
	})
	if row.Account != "present" || row.User != "alice" || row.TokenCopy != "present" || row.Setup != "not run" ||
		row.UserDataDir != userData {
		t.Fatalf("home enrollment row = %+v, want alice present with the token copy present and setup not run in %s", row, userData)
	}

	// A digest no ancestor of the recorded directory has, or no recorded
	// directory, stays unknown: nothing is guessed.
	for _, enrollment := range []acp.EnterpriseEnrollment{
		{Principal: "home:" + strings.Repeat("0", 64), ClientID: "zed", AgentID: "kiro", Profile: "locked", UserDataDir: userData},
		{Principal: principal, ClientID: "zed", AgentID: "kiro", Profile: "locked"},
	} {
		if row := describeEnterpriseACPEnrollment(enrollment); row.Account != "unknown" || row.TokenCopy != "unknown" || row.Setup != "unknown" {
			t.Fatalf("row = %+v for %+v, want unknown", row, enrollment)
		}
	}
}
