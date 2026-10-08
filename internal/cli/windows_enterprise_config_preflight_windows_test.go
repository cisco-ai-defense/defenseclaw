// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// GAP-0966: a destination secret read from an environment variable is
// refused before anything changes, set or unset, naming the destination and
// the protected-credential fields, never the per-user `keys set`.
func TestWindowsStandaloneConfigPreflightRefusesEnvironmentSecrets(t *testing.T) {
	source, layout := windowsEnterpriseStandaloneConfigSource, windowsEnterpriseStandaloneLayoutForPreflight
	windowsEnterpriseStandaloneConfigSource = func(string) error { return nil }
	windowsEnterpriseStandaloneLayoutForPreflight = func() (managed.StandaloneLayout, error) {
		return managed.StandaloneLayout{}, errors.New("no layout in this test")
	}
	t.Cleanup(func() {
		windowsEnterpriseStandaloneConfigSource, windowsEnterpriseStandaloneLayoutForPreflight = source, layout
	})
	path := filepath.Join(t.TempDir(), "w3-envref.yaml")
	body := "config_version: 9\nobservability:\n  destinations:\n    - name: eoi-hec\n      kind: splunk_hec\n" +
		"      endpoint: https://hec.example.test:8088/services/collector\n      token_env: EO3_REF\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{"", "set"} {
		t.Setenv("EO3_REF", value)
		err := windowsEnterpriseStandaloneConfigPreflight(path)
		got := ""
		if err != nil {
			got = err.Error()
		}
		for _, want := range []string{"(eoi-hec) token_env reads a secret from an environment variable", "token_credential",
			"enterprise secret set", "nothing was changed"} {
			if !strings.Contains(got, want) {
				t.Fatalf("EO3_REF=%q: preflight = %q, want it to contain %q", value, got, want)
			}
		}
		if strings.Contains(got, "keys set") {
			t.Fatalf("EO3_REF=%q: preflight names the per-user keys set: %q", value, got)
		}
	}
}
