//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

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
