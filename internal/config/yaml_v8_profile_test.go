// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"errors"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// GAP-0023, GAP-0125, GAP-0128, r103.GAP-0085: a managed config_version 9
// document whose enterprise.profile does not resolve is refused at
// enterprise.profile, not as a config_version a newer release wrote.
func TestParseV8YAMLRefusesABadProfileAtTheProfile(t *testing.T) {
	t.Setenv(managed.DeploymentModeEnv, "")
	doc := func(profile string) []byte {
		return []byte("config_version: 9\ndeployment_mode: managed_enterprise\nenterprise:\n  profile: " + profile + "\n")
	}
	for _, tc := range []struct {
		name, pin, profile, want string
	}{
		{"unknown name", "", "w0-invalid-profile", "is not a supported profile"},
		{"empty string", "", `""`, "is not a supported profile"},
		{"whitespace string", "", `"  "`, "is not a supported profile"},
		{"list", "", "[standalone]", "must be a string"},
		{"mapping", "", "{name: standalone}", "must be a string"},
		{"integer", "", "123", "must be a string"},
		{"boolean", "", "true", "must be a string"},
		{"null", "", "null", "must be a string"},
		{"unknown name with pin", managed.ProfileStandalone, "nope", "is not a supported profile"},
		{"other than the pin", managed.ProfileStandalone, managed.ProfileSecureClient, "fixed to standalone on this host"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(managed.EnterpriseProfileEnv, tc.pin)
			_, err := ParseV8YAML("/etc/defenseclaw/config.yaml", doc(tc.profile))
			var yamlErr *V8YAMLError
			if !errors.As(err, &yamlErr) || yamlErr.Code != V8YAMLErrorProfileInvalid || yamlErr.Path != "$.enterprise.profile" ||
				yamlErr.Line != 4 || !strings.Contains(yamlErr.Summary, tc.want) {
				t.Fatalf("ParseV8YAML = %v, want %s at $.enterprise.profile line 4 (%q)", err, V8YAMLErrorProfileInvalid, tc.want)
			}
			if strings.Contains(yamlErr.Summary+yamlErr.Action, "config_version") || strings.Contains(yamlErr.Summary+yamlErr.Action, managed.EnterpriseProfileEnv) {
				t.Fatalf("refusal blames config_version or names the service variable: %v", err)
			}
		})
	}
	t.Run("secure_client on Linux", func(t *testing.T) {
		if runtime.GOOS != "linux" {
			t.Skip("Linux only")
		}
		t.Setenv(managed.EnterpriseProfileEnv, "")
		_, err := ParseV8YAML("/etc/defenseclaw/config.yaml", doc("secure_client  # linux"))
		var yamlErr *V8YAMLError
		if !errors.As(err, &yamlErr) || yamlErr.Code != V8YAMLErrorProfileInvalid || !strings.Contains(yamlErr.Summary, "fixed to standalone on Linux") {
			t.Fatalf("ParseV8YAML = %v", err)
		}
		if !strings.Contains(yamlErr.Action, "changing the profile needs a reinstall of the deployment") {
			t.Fatalf("profile refusal omits the deployment recovery: %v", err)
		}
	})
	t.Run("matching pin", func(t *testing.T) {
		t.Setenv(managed.EnterpriseProfileEnv, managed.ProfileStandalone)
		if _, err := ParseV8YAML("/etc/defenseclaw/config.yaml", doc("standalone  # ok")); err != nil {
			t.Fatalf("a standalone document on a standalone host was refused: %v", err)
		}
	})
	t.Run("not managed", func(t *testing.T) {
		t.Setenv(managed.EnterpriseProfileEnv, "")
		_, err := ParseV8YAML("/tmp/config.yaml", []byte("config_version: 9\nenterprise:\n  profile: nope\n"))
		var yamlErr *V8YAMLError
		if errors.As(err, &yamlErr) && yamlErr.Code == V8YAMLErrorProfileInvalid {
			t.Fatalf("a per-user document got the managed profile refusal: %v", err)
		}
	})
}
