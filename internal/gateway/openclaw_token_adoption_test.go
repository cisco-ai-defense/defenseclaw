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

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

// oldAdoptedMarker is the comment a 1.0.9 auth repair wrote next to the
// OpenClaw token it copied under both names. 1.0.10 readers treat it as an
// ordinary comment.
const oldAdoptedMarker = "# defenseclaw: adopted gateway token sha256=0000"

// R-TOK upgrade: every 1.0.8 / 1.0.9 layout in which the DefenseClaw gateway
// token was (or would resolve to) the OpenClaw token gets a separate, newly
// minted DEFENSECLAW_GATEWAY_TOKEN at the first boot, and OPENCLAW_GATEWAY_TOKEN
// stays the OpenClaw credential. A separate master is kept as it is.
func TestEnsureGatewayTokenSeparatesTheMasterFromTheOpenClawToken(t *testing.T) {
	for _, tc := range []struct {
		name      string
		dotenv    string
		envMaster string
		envOC     string
		notMaster []string
		keep      string
	}{
		{name: "only OPENCLAW_GATEWAY_TOKEN (1.0.8 setup gateway)", dotenv: "OPENCLAW_GATEWAY_TOKEN=oc-token\n"},
		{name: "both names hold the OpenClaw token (1.0.9 auth repair)", dotenv: "DEFENSECLAW_GATEWAY_TOKEN=oc-token\nOPENCLAW_GATEWAY_TOKEN=oc-token\n" + oldAdoptedMarker + "\n"},
		{name: "master equals the openclaw.json token", dotenv: "DEFENSECLAW_GATEWAY_TOKEN=oc-token\n", notMaster: []string{"oc-token"}},
		{name: "exported master equals the exported OpenClaw token", dotenv: "", envMaster: "oc-token", envOC: "oc-token"},
		{name: "separate master is kept", dotenv: "DEFENSECLAW_GATEWAY_TOKEN=master-token\nOPENCLAW_GATEWAY_TOKEN=oc-token\n", notMaster: []string{"oc-token"}, keep: "master-token"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("DEFENSECLAW_GATEWAY_TOKEN", tc.envMaster)
			t.Setenv("OPENCLAW_GATEWAY_TOKEN", tc.envOC)
			envPath := filepath.Join(t.TempDir(), ".env")
			if err := os.WriteFile(envPath, []byte(tc.dotenv), 0o600); err != nil {
				t.Fatal(err)
			}
			got, err := EnsureGatewayToken(envPath, tc.notMaster...)
			if err != nil {
				t.Fatalf("EnsureGatewayToken: %v", err)
			}
			env, err := loadDotEnv(envPath)
			if err != nil {
				t.Fatal(err)
			}
			if tc.keep != "" {
				if got != tc.keep {
					t.Fatalf("token = %q, want the separate master kept", got)
				}
			} else {
				if got == "" || got == "oc-token" || len(got) != 64 {
					t.Fatalf("token = %q, want a newly minted 64-hex token", got)
				}
				if env["DEFENSECLAW_GATEWAY_TOKEN"] != got {
					t.Fatalf(".env DEFENSECLAW_GATEWAY_TOKEN = %q, want the minted token", env["DEFENSECLAW_GATEWAY_TOKEN"])
				}
			}
			if strings.Contains(tc.dotenv, "OPENCLAW_GATEWAY_TOKEN=oc-token") && env["OPENCLAW_GATEWAY_TOKEN"] != "oc-token" {
				t.Fatalf(".env OPENCLAW_GATEWAY_TOKEN = %q, want oc-token kept", env["OPENCLAW_GATEWAY_TOKEN"])
			}
			// Idempotent: the next boot reads the same master back.
			if tc.envMaster == "" {
				again, err := EnsureGatewayToken(envPath, tc.notMaster...)
				if err != nil || again != got {
					t.Fatalf("second call = %q, %v, want %q", again, err, got)
				}
			}
		})
	}
}

func saveOpenClawToken(t *testing.T, dir, token string) error {
	t.Helper()
	return appendEnvLine(filepath.Join(dir, ".env"), "OPENCLAW_GATEWAY_TOKEN", token)
}

// The OpenClaw token adoption builds the whole new .env first. A file that comes out at the
// size every reader accepts is published; one byte over is refused with the
// cause, the current file stays as it was, and its token still resolves.
func TestAdoptionPublishesAMaximumSizeDotenvAndRefusesOneByteOver(t *testing.T) {
	const oldToken, newToken = "old-token", "new-token-one-byte-longer"
	tokens := "DEFENSECLAW_GATEWAY_TOKEN=master-token\nOPENCLAW_GATEWAY_TOKEN=" + oldToken + "\n"
	// What the adoption adds to the original: the longer OpenClaw token.
	growth := len(newToken) - len(oldToken)
	for _, tc := range []struct {
		name   string
		over   int
		ending string
	}{
		{"exact limit", 0, "\n"},
		{"exact limit without final newline", 0, ""},
		{"one byte over", 1, "\n"},
		{"one byte over without final newline", 1, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("DEFENSECLAW_GATEWAY_TOKEN", "")
			t.Setenv("OPENCLAW_GATEWAY_TOKEN", "")
			dir := t.TempDir()
			envPath := filepath.Join(dir, ".env")
			// The file is padded so the adopted result is exactly MaxDotEnvBytes + over.
			// A file with no final newline gains one from the adoption.
			gain := growth
			if tc.ending == "" {
				gain++
			}
			pad := safefile.MaxDotEnvBytes + tc.over - gain - len(tokens) - 1 - len(tc.ending)
			original := []byte(tokens + "#" + strings.Repeat("x", pad) + tc.ending)
			if err := os.WriteFile(envPath, original, 0o600); err != nil {
				t.Fatal(err)
			}
			err := saveOpenClawToken(t, dir, newToken)
			after, readErr := os.ReadFile(envPath)
			if readErr != nil {
				t.Fatal(readErr)
			}
			want := newToken
			if tc.over > 0 {
				want = oldToken
				if err == nil || !strings.Contains(err.Error(), "over the") || !strings.Contains(err.Error(), "limit") {
					t.Fatalf("err = %v, want a refusal naming the size limit", err)
				}
				if string(after) != string(original) {
					t.Fatalf("a refused adoption changed the .env (%d bytes -> %d)", len(original), len(after))
				}
			} else if err != nil {
				t.Fatalf("saveOpenClawToken: %v", err)
			} else if len(after) != safefile.MaxDotEnvBytes {
				t.Fatalf("size = %d, want exactly %d", len(after), safefile.MaxDotEnvBytes)
			}
			env, err := loadDotEnv(envPath)
			if err != nil || env["OPENCLAW_GATEWAY_TOKEN"] != want {
				t.Fatalf("OpenClaw token = %q, %v, want %q", env["OPENCLAW_GATEWAY_TOKEN"], err, want)
			}
			if got, err := EnsureGatewayToken(envPath); err != nil || got != "master-token" {
				t.Fatalf("gateway token = %q, %v, want master-token unchanged", got, err)
			}
		})
	}
}

// The adoption keeps the line ending the file has: every line CRLF in a CRLF
// file and every line LF in an LF file, never a mix. The token reads back from
// both.
func TestAdoptionWritesOneLineEndingAndTheTokenReadsBack(t *testing.T) {
	for _, tc := range []struct{ name, eol string }{
		{"lf", "\n"},
		{"crlf", "\r\n"},
	} {
		for _, final := range []bool{true, false} {
			name := tc.name
			if !final {
				name += " without final newline"
			}
			t.Run(name, func(t *testing.T) {
				t.Setenv("DEFENSECLAW_GATEWAY_TOKEN", "")
				t.Setenv("OPENCLAW_GATEWAY_TOKEN", "")
				dir := t.TempDir()
				envPath := filepath.Join(dir, ".env")
				before := strings.Join([]string{"DEFENSECLAW_LLM_KEY=keep", "DEFENSECLAW_GATEWAY_TOKEN=old-token", "# note"}, tc.eol)
				if final {
					before += tc.eol
				}
				if err := os.WriteFile(envPath, []byte(before), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := saveOpenClawToken(t, dir, "adopted-token"); err != nil {
					t.Fatal(err)
				}
				body, err := os.ReadFile(envPath)
				if err != nil {
					t.Fatal(err)
				}
				text := string(body)
				if !strings.HasSuffix(text, tc.eol) || strings.Count(text, "\n") != strings.Count(text, tc.eol) {
					t.Fatalf("not one %q line ending throughout: %q", tc.eol, text)
				}
				lines := strings.Split(strings.TrimSuffix(text, tc.eol), tc.eol)
				for _, want := range []string{
					"DEFENSECLAW_LLM_KEY=keep",
					"DEFENSECLAW_GATEWAY_TOKEN=old-token",
					"OPENCLAW_GATEWAY_TOKEN=adopted-token",
				} {
					n := 0
					for _, line := range lines {
						if line == want {
							n++
						}
					}
					if n != 1 {
						t.Fatalf("want one line %q, found %d in %q", want, n, text)
					}
				}
				got, err := EnsureGatewayToken(envPath)
				if err != nil || got != "old-token" {
					t.Fatalf("token = %q, %v, want the gateway token unchanged by the adoption", got, err)
				}
			})
		}
	}
}

// The sidecar refuses a gateway token equal to the openclaw.json
// gateway.auth.token even when no OPENCLAW_GATEWAY_TOKEN is saved, and keeps
// a separate one.
func TestMasterGatewayTokenRefusesTheOpenClawJSONToken(t *testing.T) {
	home := t.TempDir()
	writeOpenClawJSON(t, home, `{"gateway":{"auth":{"token":"json-oc-token"}}}`)
	t.Setenv("OPENCLAW_GATEWAY_TOKEN", "")
	cfg := &config.Config{}
	cfg.Gateway.ClawHome = home

	t.Setenv("DEFENSECLAW_GATEWAY_TOKEN", "json-oc-token")
	if tok, needed := masterGatewayToken(cfg); !needed || tok != "" {
		t.Fatalf("master equal to openclaw.json: (%q, %v), want a mint", tok, needed)
	}
	t.Setenv("DEFENSECLAW_GATEWAY_TOKEN", "master-token")
	if tok, needed := masterGatewayToken(cfg); needed || tok != "master-token" {
		t.Fatalf("separate master: (%q, %v), want it kept", tok, needed)
	}
	if got := openClawGatewayTokens(&cfg.Gateway); len(got) != 1 || got[0] != "json-oc-token" {
		t.Fatalf("openClawGatewayTokens = %v, want [json-oc-token]", got)
	}
}
