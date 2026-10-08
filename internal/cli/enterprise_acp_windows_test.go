//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/acp"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"golang.org/x/sys/windows"
)

// An unknown account and an account that never signed in are refused in
// words: the LSA text with doubled backslashes (GAP-0735), and "deleted ...
// run Setup /ensure" (GAP-0715).
func TestEnterpriseACPWindowsAccountRefusalsArePlain(t *testing.T) {
	previous := enterpriseHookSIDProfilePath
	t.Cleanup(func() { enterpriseHookSIDProfilePath = previous })
	cause := fmt.Errorf("enterprise hooks: lookup user %q: %w", `HOST\nosuchuser`, windows.ERROR_NONE_MAPPED)
	if got := enterpriseACPPlainError(cause, `HOST\nosuchuser`).Error(); !strings.Contains(got, `no account named HOST\nosuchuser on this computer`) ||
		strings.Contains(got, `\\`) || strings.Contains(got, "mapping") {
		t.Fatalf("unknown account refusal = %q", got)
	}
	enterpriseHookSIDProfilePath = func(string) (string, error) { return "", os.ErrNotExist }
	if got := enterpriseACPNoHomeText(`HOST\dcw-new`, `C:\Users\dcw-new`, "S-1-5-21-1-2-3-1002"); !strings.Contains(got, "has not signed in") ||
		strings.Contains(got, "/ensure") {
		t.Fatalf("never-signed-in refusal = %q", got)
	}
}

// A transient LSA failure cannot prove that an enrolled account was deleted.
func TestEnterpriseACPWindowsListKeepsUnknownLookupFailures(t *testing.T) {
	previous := enterpriseACPLookupWindowsAccount
	t.Cleanup(func() { enterpriseACPLookupWindowsAccount = previous })
	const principal = "sid:S-1-5-21-1-2-3-1117"
	enterpriseACPLookupWindowsAccount = func(string) (string, string, error) {
		return "", "", windows.ERROR_TIMEOUT
	}
	row := describeEnterpriseACPEnrollment(acp.EnterpriseEnrollment{Principal: principal})
	if row.Account != "unknown" || row.TokenCopy != "unknown" || row.Setup != "unknown" {
		t.Fatalf("transient lookup listed as %+v", row)
	}
	enterpriseACPLookupWindowsAccount = func(string) (string, string, error) {
		return "", "", windows.ERROR_NONE_MAPPED
	}
	row = describeEnterpriseACPEnrollment(acp.EnterpriseEnrollment{Principal: principal})
	if row.Account != "deleted" {
		t.Fatalf("definitive missing account listed as %+v", row)
	}
}

// revoke --sid of an account with no profile any more acts on its service
// record; it failed on the profile lookup (GAP-0367).
func TestEnterpriseACPSIDWithoutProfileIsRevocable(t *testing.T) {
	previousCfg, previousPath := cfg, enterpriseHookSIDProfilePath
	previous := []string{enterpriseACPClient, enterpriseACPAgent, enterpriseACPProfile, enterpriseACPUser, enterpriseACPUserHome, enterpriseACPSID}
	t.Cleanup(func() {
		cfg, enterpriseHookSIDProfilePath = previousCfg, previousPath
		enterpriseACPClient, enterpriseACPAgent, enterpriseACPProfile = previous[0], previous[1], previous[2]
		enterpriseACPUser, enterpriseACPUserHome, enterpriseACPSID = previous[3], previous[4], previous[5]
	})
	cfg = &config.Config{DataDir: t.TempDir(), DeploymentMode: "managed_enterprise"}
	cfg.Enterprise.Profile = "standalone"
	enterpriseHookSIDProfilePath = func(string) (string, error) { return "", os.ErrNotExist }
	enterpriseACPClient, enterpriseACPAgent, enterpriseACPProfile = "zed", "hermes", "w2w-obs"
	enterpriseACPUser, enterpriseACPUserHome, enterpriseACPSID = "", "", "s-1-5-21-1-2-3-1117"
	enrollment, err := resolveEnterpriseACPEnrollment(false)
	if err != nil || !enrollment.accountGone || enrollment.principal != "sid:S-1-5-21-1-2-3-1117" {
		t.Fatalf("enrollment = %+v, err = %v; want the service record of the SID", enrollment, err)
	}
}
