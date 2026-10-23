// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// GAP-0023, GAP-0125, GAP-0128, r103.GAP-0085, p0.GAP-0580: a bad
// enterprise.profile is refused at enterprise.profile, never as an
// unsupported config_version 9, and a profile other than the fixed one says
// that changing it needs a reinstall, without naming the service variable.
func TestEnsureRefusesABadProfileAtTheProfile(t *testing.T) {
	for _, tc := range []struct {
		goos, profile string
		want          []string
	}{
		{"linux", "w0-invalid-profile", []string{"enterprise.profile is not a supported profile", "set it to standalone"}},
		{"linux", "secure_client", []string{"enterprise.profile is fixed to standalone on this host", "needs a reinstall"}},
		{"darwin", "w0-invalid-profile", []string{"enterprise.profile is not a supported profile", "set it to standalone"}},
		{"darwin", "secure_client", []string{"enterprise.profile is fixed to standalone on this host", "needs a reinstall"}},
	} {
		t.Run(tc.goos+"/"+tc.profile, func(t *testing.T) {
			h := newTestHost(t, tc.goos)
			path := filepath.Join(t.TempDir(), "admin.yaml")
			raw := strings.Replace(string(DefaultConfig(h.env.Layout)), "profile: standalone", "profile: "+tc.profile, 1)
			if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
				t.Fatal(err)
			}
			r := h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0"), ConfigFile: path})
			requireError(t, r, codeConfig)
			got := r.Errors[0].Message
			if !strings.HasPrefix(got, path+" line 9: ") {
				t.Fatalf("message %q does not name the profile line of %s", got, path)
			}
			for _, want := range tc.want {
				if !strings.Contains(got, want) {
					t.Fatalf("message %q lacks %q", got, want)
				}
			}
			for _, jargon := range []string{"config_version", "newer DefenseClaw", "DEFENSECLAW_ENTERPRISE_PROFILE", "[", "$."} {
				if strings.Contains(got, jargon) {
					t.Fatalf("message keeps %q: %s", jargon, got)
				}
			}
		})
	}
}

// GAP-0547: a rule pack the gateway cannot build (an unknown pack, a
// digest that does not match) is refused in the same plain words as the
// other config refusals: the file, the setting and the fix, without the
// validator's rule id or a JSONPath.
func TestEnsureWordsAnUnbuildablePackPlainly(t *testing.T) {
	h := newTestHost(t, "linux")
	config.RegisterCandidateAssetCheck(func(*config.Config) error {
		return errors.New(`config rule pack "nosuchpack" is neither built in (default, strict, permissive) nor a guardrail.custom_packs entry`)
	})
	t.Cleanup(func() { config.RegisterCandidateAssetCheck(nil) })
	path := filepath.Join(t.TempDir(), "admin.yaml")
	if err := os.WriteFile(path, DefaultConfig(h.env.Layout), 0o600); err != nil {
		t.Fatal(err)
	}
	r := h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0"), ConfigFile: path})
	requireError(t, r, codeConfig)
	got := r.Errors[0].Message
	if !strings.HasPrefix(got, path+": guardrail: ") || !strings.Contains(got, `config rule pack "nosuchpack" is neither built in`) ||
		!strings.Contains(got, settingsReferenceURL) {
		t.Fatalf("message = %q", got)
	}
	for _, jargon := range []string{"config_semantic_invalid", "[", "$.", "<config>", "does not build"} {
		if strings.Contains(got, jargon) {
			t.Fatalf("message keeps %q: %s", jargon, got)
		}
	}
}
