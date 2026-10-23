// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterpriseunix"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// onStandaloneManagedHost makes config validate run as on a standalone
// managed host whose layout lives under a temporary root.
func onStandaloneManagedHost(t *testing.T) managed.StandaloneLayout {
	t.Helper()
	layout, err := managed.StandaloneLayoutFor(runtime.GOOS)
	if err != nil {
		t.Skip(err)
	}
	root := t.TempDir()
	layout.SecretsDir = filepath.Join(root, "secrets")
	previousHost, previousEnv, previousLayout := configValidateManagedHost, newUnixLifecycleEnv, configValidateStandaloneLayout
	configValidateManagedHost = func() bool { return true }
	newUnixLifecycleEnv = func(goos string) (*enterpriseunix.Env, error) {
		return &enterpriseunix.Env{GOOS: goos, Root: root, Layout: layout, Geteuid: func() int { return 0 }}, nil
	}
	configValidateStandaloneLayout = func(string) (managed.StandaloneLayout, error) { return layout, nil }
	t.Setenv(managed.DeploymentModeEnv, "")
	t.Setenv(managed.EnterpriseProfileEnv, "")
	t.Setenv(managed.ConfigPathEnv, filepath.Join(root, "installed", "config.yaml"))
	t.Cleanup(func() {
		configValidateManagedHost, newUnixLifecycleEnv, configValidateStandaloneLayout = previousHost, previousEnv, previousLayout
		configValidateCmd.SetOut(nil)
		configValidateJSON, configValidateDataDir = false, ""
	})
	return layout
}

func runConfigValidate(t *testing.T, body string, asJSON bool) (string, string, error) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "candidate.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	configValidateDataDir, configValidateJSON = dir, asJSON
	out := &strings.Builder{}
	configValidateCmd.SetOut(out)
	err := configValidateCmd.RunE(configValidateCmd, []string{path})
	return path, out.String(), err
}

const managedValidateHead = "config_version: 9\ndeployment_mode: managed_enterprise\nenterprise:\n  profile: standalone\n"

// r103.GAP-0087, r103.GAP-0088, GAP-0023: on a standalone managed host
// config validate words a refusal the way ensure does, in one plain sentence
// with the file, the setting and the fix, and the JSON result carries the
// same sentence.
func TestConfigValidateOnManagedHostRefusesInPlainWords(t *testing.T) {
	onStandaloneManagedHost(t)
	for _, tc := range []struct {
		name, body string
		want       []string
	}{
		{"unknown key", managedValidateHead + "r103_unknown_key: true\n", []string{"r103_unknown_key is an unknown setting", "The settings reference"}},
		{"duplicate key", managedValidateHead + "guardrail:\n  mode: observe\n  mode: action\n", []string{"guardrail.mode appears twice"}},
		{"bad profile", strings.Replace(managedValidateHead, "profile: standalone", "profile: w0-invalid-profile", 1),
			[]string{"line 4: enterprise.profile is not a supported profile"}},
		{"proxy scheme", managedValidateHead + "  network:\n    https_proxy: socks5://proxy.example.test:1080\n", []string{"enterprise.network.https_proxy", "http://", "https://"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path, out, err := runConfigValidate(t, tc.body, true)
			if err == nil {
				t.Fatal("config validate accepted the candidate")
			}
			message := err.Error()
			if !strings.HasPrefix(message, path) {
				t.Fatalf("refusal %q does not name %s", message, path)
			}
			for _, want := range tc.want {
				if !strings.Contains(message, want) {
					t.Fatalf("refusal %q lacks %q", message, want)
				}
			}
			for _, jargon := range []string{"[config_", "[yaml_", "[enterprise_", " $.", "is not valid at", "config_version", "proxy.example.test", "withheld"} {
				if strings.Contains(message, jargon) {
					t.Fatalf("refusal keeps %q: %s", jargon, message)
				}
			}
			var failure configV8WireFailure
			if json.Unmarshal([]byte(out), &failure) != nil || failure.Kind != "validation_error" || failure.Message != message {
				t.Fatalf("JSON = %q, want the validation_error with message %q", out, message)
			}
		})
	}
}

// A per-user host keeps the validator's diagnostic.
func TestConfigValidateOffManagedHostKeepsTheDiagnostic(t *testing.T) {
	onStandaloneManagedHost(t)
	configValidateManagedHost = func() bool { return false }
	_, out, err := runConfigValidate(t, "config_version: 9\nr103_unknown_key: true\n", true)
	if err == nil || !strings.Contains(err.Error(), "is not valid at $.r103_unknown_key: [config_schema_invalid]") || strings.Contains(out, `"message"`) {
		t.Fatalf("config validate = %v (out %q), want the diagnostic", err, out)
	}
}

// GAP-0122: on a standalone managed host a candidate's protected credential
// references resolve from the installed deployment's secrets directory, the
// one ensure checks, wherever the candidate file is kept.
func TestConfigValidateResolvesCredentialsFromTheInstalledSecrets(t *testing.T) {
	layout := onStandaloneManagedHost(t)
	dir := t.TempDir()
	standalone := filepath.Join(dir, "standalone.yaml")
	perUser := filepath.Join(dir, "per-user.yaml")
	if err := os.WriteFile(standalone, []byte(managedValidateHead), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(perUser, []byte("config_version: 9\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := configValidateCredentialsDir(standalone); got != layout.SecretsDir {
		t.Fatalf("credentials dir = %q, want the installed %q", got, layout.SecretsDir)
	}
	if got := configValidateCredentialsDir(perUser); got != "" {
		t.Fatalf("a per-user source resolves credentials from %q", got)
	}
	configValidateManagedHost = func() bool { return false }
	if got := configValidateCredentialsDir(standalone); got != "" {
		t.Fatalf("a host that is not managed resolves credentials from %q", got)
	}
}
