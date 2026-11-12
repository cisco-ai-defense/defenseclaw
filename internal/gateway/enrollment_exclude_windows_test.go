// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package gateway

import (
	"os/user"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// GAP-1111: on Windows the LSA decides. An account the host has, named bare,
// is not listed; a bare name and an AzureAD\ name it maps to no account are,
// by position, without their text. The account the host has is the one the
// test runs as: a hosted Windows runner has no account the LSA maps to the
// bare name Administrator (Windows Native CI 43322960003, rel-1-0-10
// GAP-0044).
func TestWindowsStandaloneStatusNamesExcludeEntriesThatMatchNoAccount(t *testing.T) {
	current, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	own := current.Username
	if i := strings.LastIndexByte(own, '\\'); i >= 0 {
		own = own[i+1:]
	}
	cfg := &config.Config{DeploymentMode: "managed_enterprise"}
	cfg.Enterprise.Profile = "standalone"
	cfg.Enterprise.Enrollment.ExcludeUsers = []string{`BUILTIN\Administrators`, own, "r106fxe8-nosuch-acct", `AzureAD\r106fxe8-nobody`}
	var got []string
	for _, warning := range standaloneProfileWarnings(nil, cfg) {
		if strings.Contains(warning, "exclude_users") {
			got = append(got, warning)
		}
	}
	if len(got) != 1 || !strings.Contains(got[0], "2 entries (position 3, 4 in the list) match no account") ||
		strings.Contains(got[0], "r106fxe8") {
		t.Fatalf("exclude warnings = %q", got)
	}
}
