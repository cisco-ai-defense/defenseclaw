// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

func TestEnterpriseProfileDiagnosticKeepsSourceVersionAndField(t *testing.T) {
	t.Setenv(managed.DeploymentModeEnv, "")
	t.Setenv(managed.EnterpriseProfileEnv, managed.ProfileStandalone)
	for _, value := range []string{`""`, `"  "`, "w0-invalid", "[standalone]", "{name: standalone}", "123", "true", "null"} {
		t.Run(value, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "config.yaml")
			if err := os.WriteFile(path, []byte("config_version: 9\ndeployment_mode: managed_enterprise\nenterprise:\n  profile: "+value+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := loadConfigV8File(path, dir)
			if err == nil {
				t.Fatal("invalid enterprise profile accepted")
			}
			raw, err := json.Marshal(configV8ValidationFailure(err))
			if err != nil {
				t.Fatal(err)
			}
			var failure configV8WireFailure
			if err := json.Unmarshal(raw, &failure); err != nil || failure.ConfigVersion != 9 || failure.Path != "$.enterprise.profile" || !strings.Contains(failure.Reason, "enterprise_profile_invalid") {
				t.Fatalf("diagnostic=%s, error=%v", raw, err)
			}
		})
	}
}
