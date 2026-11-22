// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/cli/substratecli/auth"
)

// GAP-0421: login keeps a CA file given as a relative path as an absolute
// one, so a later command from another folder still reads it.
func TestSubstrateLoginStoresAbsoluteCAPathsGAP0421(t *testing.T) {
	home, work, elsewhere := t.TempDir(), t.TempDir(), t.TempDir()
	t.Setenv("DEFENSECLAW_HOME", home)
	for _, name := range []string{"lab-ca.pem", "sso-ca.pem"} {
		if err := os.WriteFile(filepath.Join(work, name), []byte("-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	enc := base64.RawURLEncoding.EncodeToString
	claims, _ := json.Marshal(map[string]any{"iss": "https://ci.example.test", "sub": "repo:x", "aud": "defenseclaw", "exp": time.Now().Add(time.Hour).Unix()})
	tok := filepath.Join(work, "ci-token")
	if err := os.WriteFile(tok, []byte(enc([]byte(`{"alg":"RS256"}`))+"."+enc(claims)+".c2ln"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Chdir(work)
	if _, _, err := runSubstrate(t, newSubstrateLoginCmd(), "--name", "lab", "--admin-url", "https://127.0.0.1:1",
		"--admin-ca-file", "lab-ca.pem", "--issuer-ca-file", "./sso-ca.pem", "--workload", "--workload-token-file", tok); err != nil {
		t.Fatalf("login: %v", err)
	}
	t.Chdir(elsewhere)
	cf, err := auth.LoadContexts()
	if err != nil {
		t.Fatal(err)
	}
	c := cf.Contexts["lab"]
	for flag, got := range map[string]string{"admin-ca-file": c.AdminCAFile, "issuer-ca-file": c.IssuerCAFile} {
		if !filepath.IsAbs(got) {
			t.Errorf("--%s saved as %q, not an absolute path", flag, got)
			continue
		}
		if _, err := os.Stat(got); err != nil {
			t.Errorf("--%s saved as %q, unreadable from another folder: %v", flag, got, err)
		}
	}
}
