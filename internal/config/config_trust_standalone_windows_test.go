// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package config

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// GAP-0561: a standalone managed process refuses a config.yaml with an
// untrusted writer, as before 26.8.4. The Secure Client twin, which accepts
// and logs it, is TestLoadFromFile_ManagedEnterpriseUntrustedWriterOnConfigPath.
func TestLoadFromFile_StandaloneManagedRefusesUntrustedWriterOnConfigPath(t *testing.T) {
	isolateManagedTrustEnv(t)
	path := writeUntrustedManagedConfigForTest(t, func(dir string) string {
		return "config_version: 8\ndeployment_mode: managed_enterprise\ndata_dir: " + dir + "\n"
	})
	t.Setenv(managed.DeploymentModeEnv, string(DeploymentModeManagedEnterprise))
	t.Setenv(managed.EnterpriseProfileEnv, managed.ProfileStandalone)
	_, err := LoadFromFile(path)
	if err == nil || !strings.Contains(err.Error(), "managed_enterprise config trust check failed") {
		t.Fatalf("LoadFromFile error = %v, want the standalone managed trust refusal", err)
	}
}
