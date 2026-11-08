// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

// The gateway writes an adopted token under both spellings. An operator who
// then edits one spelling saved a newer token, and the adopted copy under the
// other spelling must not win at the next start (GAP-0847).
func TestEnsureGatewayTokenPrefersAnEditedSpellingOverTheAdoptedCopy(t *testing.T) {
	for _, tc := range []struct {
		name   string
		edited string
	}{
		{"legacy spelling edited", "OPENCLAW_GATEWAY_TOKEN"},
		{"canonical spelling edited", "DEFENSECLAW_GATEWAY_TOKEN"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("DEFENSECLAW_GATEWAY_TOKEN", "")
			t.Setenv("OPENCLAW_GATEWAY_TOKEN", "")
			dir := t.TempDir()
			envPath := filepath.Join(dir, ".env")
			if err := persistRefreshedToken(dir, "adopted-token"); err != nil {
				t.Fatal(err)
			}
			body, err := os.ReadFile(envPath)
			if err != nil {
				t.Fatal(err)
			}
			edited := strings.Replace(string(body), tc.edited+"=adopted-token", tc.edited+"=edited-token", 1)
			if edited == string(body) {
				t.Fatalf("adoption wrote no %s line:\n%s", tc.edited, body)
			}
			if err := os.WriteFile(envPath, []byte(edited), 0o600); err != nil {
				t.Fatal(err)
			}
			got, err := EnsureGatewayToken(envPath)
			if err != nil {
				t.Fatal(err)
			}
			if got != "edited-token" {
				t.Fatalf("token = %q, want the edited token", got)
			}
			env, err := loadDotEnv(envPath)
			if err != nil {
				t.Fatal(err)
			}
			if env["DEFENSECLAW_GATEWAY_TOKEN"] == "adopted-token" || env["OPENCLAW_GATEWAY_TOKEN"] == "adopted-token" {
				t.Fatalf("the adopted copy is still read: %v", env)
			}
		})
	}
}

// The twin: an adoption nobody edited reads back unchanged, and a re-adoption
// replaces the marker so the previous one does not hide the new copy.
func TestEnsureGatewayTokenKeepsAnUneditedAdoptedToken(t *testing.T) {
	t.Setenv("DEFENSECLAW_GATEWAY_TOKEN", "")
	t.Setenv("OPENCLAW_GATEWAY_TOKEN", "")
	dir := t.TempDir()
	envPath := filepath.Join(dir, ".env")
	for _, token := range []string{"first-adopted", "second-adopted"} {
		if err := persistRefreshedToken(dir, token); err != nil {
			t.Fatal(err)
		}
		got, err := EnsureGatewayToken(envPath)
		if err != nil || got != token {
			t.Fatalf("token = %q, %v, want %q", got, err, token)
		}
	}
	body, _ := os.ReadFile(envPath)
	if n := strings.Count(string(body), "adopted gateway token sha256="); n != 1 {
		t.Fatalf("want one marker line, found %d:\n%s", n, body)
	}
}

// A .env at the size every reader accepts stays readable after an adoption: the
// marker is provenance only and is left out rather than push the file over.
func TestAdoptionKeepsAnAcceptedMaximumSizeDotenvReadable(t *testing.T) {
	t.Setenv("DEFENSECLAW_GATEWAY_TOKEN", "")
	t.Setenv("OPENCLAW_GATEWAY_TOKEN", "")
	dir := t.TempDir()
	envPath := filepath.Join(dir, ".env")
	tokens := "DEFENSECLAW_GATEWAY_TOKEN=old-token\nOPENCLAW_GATEWAY_TOKEN=old-token\n"
	padding := "#" + strings.Repeat("x", safefile.MaxDotEnvBytes-len(tokens)-2) + "\n"
	if err := os.WriteFile(envPath, []byte(tokens+padding), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := persistRefreshedToken(dir, "new-token"); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(envPath)
	if err != nil || info.Size() > safefile.MaxDotEnvBytes {
		t.Fatalf("size = %v, %v, want at most %d", info, err, safefile.MaxDotEnvBytes)
	}
	got, err := EnsureGatewayToken(envPath)
	if err != nil || got != "new-token" {
		t.Fatalf("token = %q, %v, want new-token", got, err)
	}
}
