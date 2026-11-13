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

// GAP-1111: on Windows the LSA decides. A local account the host has is
// not listed; a bare name and an AzureAD\ name it maps to no account are,
// by position, without their text. The known account is the one running the
// test: a hosted runner has no account called Administrator (the Windows
// Native CI run 43323839711 listed it as unknown).
func TestWindowsStandaloneStatusNamesExcludeEntriesThatMatchNoAccount(t *testing.T) {
	current, err := user.Current()
	if err != nil || current.Username == "" {
		t.Fatalf("no current account to use as the known entry: %v", err)
	}
	cfg := &config.Config{DeploymentMode: "managed_enterprise"}
	cfg.Enterprise.Profile = "standalone"
	cfg.Enterprise.Enrollment.ExcludeUsers = []string{`BUILTIN\Administrators`, current.Username, "r106fxe8-nosuch-acct", `AzureAD\r106fxe8-nobody`}
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
