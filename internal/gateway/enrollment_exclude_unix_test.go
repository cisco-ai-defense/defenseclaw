// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package gateway

import (
	"errors"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
)

// GAP-1111: a standalone exclude_users entry that names no account (a bare
// name that exists nowhere, a DOMAIN\name of no account) is listed by
// position in status and verify; a known account, a failed lookup and a
// wildcard are not, and the entry text is not repeated.
func TestStandaloneStatusNamesExcludeEntriesThatMatchNoAccount(t *testing.T) {
	restore := profileExplainAccount
	t.Cleanup(func() { profileExplainAccount = restore })
	profileExplainAccount = func(name string) (string, string, error) {
		switch name {
		case "r106fxe8-alice":
			return "1001", "r106fxe8-alice", nil
		case "CORP\\r106fxe8-alice", "r106fxe8-alice@corp.test":
			// resolves, but the enumerator matches only the exact name or uid
			return "1001", "r106fxe8-alice", nil
		case "1001":
			return "1001", "r106fxe8-alice", nil
		case "r106fxe8-flaky":
			return "", "", errors.New("lookup timed out")
		}
		return "", "", unixidentity.ErrNotFound
	}
	cfg := &config.Config{DeploymentMode: "managed_enterprise"}
	cfg.Enterprise.Profile = "standalone"
	cfg.Enterprise.Enrollment.ExcludeUsers = []string{"r106fxe8-alice", "r106fxe8-nosuch", `CORP\r106fxe8-gone`, "r106fxe8-flaky", "r106fxe8-*", "CORP\\r106fxe8-alice", "r106fxe8-alice@corp.test", "1001"}
	var got []string
	for _, warning := range standaloneProfileWarnings(nil, cfg) {
		if strings.Contains(warning, "exclude_users") {
			got = append(got, warning)
		}
	}
	if len(got) != 1 || !strings.Contains(got[0], "4 entries (position 2, 3, 6, 7 in the list) match no account") ||
		strings.Contains(got[0], "r106fxe8") {
		t.Fatalf("exclude warnings = %q", got)
	}
	cfg.Enterprise.Profile = "secure_client"
	for _, warning := range standaloneProfileWarnings(nil, cfg) {
		if strings.Contains(warning, "exclude_users") {
			t.Fatalf("a Secure Client config warned %q", warning)
		}
	}
}
