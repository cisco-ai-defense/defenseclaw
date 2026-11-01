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

// rel-1-0-2 GAP-0145 on managed Windows (L-ewin-J5-023): Setup's own config
// check refused a config_version 8 candidate with update_check: false before
// the transaction's migration could move it to update.check.
func TestWindowsSetupConfigPreflightAcceptsAV8UpdateCheck(t *testing.T) {
	previousLayout, previousSource := windowsEnterpriseStandaloneLayoutForPreflight, windowsEnterpriseStandaloneConfigSource
	t.Cleanup(func() {
		windowsEnterpriseStandaloneLayoutForPreflight, windowsEnterpriseStandaloneConfigSource = previousLayout, previousSource
	})
	windowsEnterpriseStandaloneConfigSource = func(string) error { return nil }
	root := t.TempDir()
	windowsEnterpriseStandaloneLayoutForPreflight = func() (managed.StandaloneLayout, error) {
		return managed.StandaloneLayout{
			GOOS: "windows", ConfigPath: filepath.Join(root, "etc", "config.yaml"), DataDir: filepath.Join(root, "data"),
			SecretsDir: filepath.Join(root, "secrets"), ServiceUser: `NT SERVICE\DefenseClawGateway`,
		}, nil
	}
	write := func(name, body string) string {
		t.Helper()
		path := filepath.Join(root, name)
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	plain := write("plain.yaml", standaloneGatewayCheckConfig)
	baseline := windowsEnterpriseStandaloneConfigPreflight(plain)
	withKey := write("candidate.yaml", strings.Replace(standaloneGatewayCheckConfig, "config_version: 8\n", "config_version: 8\nupdate_check: false\n", 1))
	err := windowsEnterpriseStandaloneConfigPreflight(withKey)
	if err != nil && strings.Contains(err.Error(), "update_check") {
		t.Fatalf("Setup refused a v8 candidate for update_check: %v", err)
	}
	if (err == nil) != (baseline == nil) {
		t.Fatalf("the candidate with update_check = %v; the same candidate without it = %v; want the same verdict", err, baseline)
	}
}
