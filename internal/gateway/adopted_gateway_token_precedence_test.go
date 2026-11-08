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

	"github.com/defenseclaw/defenseclaw/internal/envvars"
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

// The adoption builds the whole new .env first. A file that comes out at the
// size every reader accepts is published; one byte over is refused with the
// cause, the current file stays as it was, and its token still resolves.
func TestAdoptionPublishesAMaximumSizeDotenvAndRefusesOneByteOver(t *testing.T) {
	const oldToken, newToken = "old-token", "new-token-one-byte-longer"
	tokens := "DEFENSECLAW_GATEWAY_TOKEN=" + oldToken + "\nOPENCLAW_GATEWAY_TOKEN=" + oldToken + "\n"
	// What the adoption adds to the original: the longer token under both spellings and the marker.
	growth := 2*(len(newToken)-len(oldToken)) + len(envvars.AdoptedGatewayTokenMarker(newToken)) + 1
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
			err := persistRefreshedToken(dir, newToken)
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
				t.Fatalf("persistRefreshedToken: %v", err)
			} else if len(after) != safefile.MaxDotEnvBytes {
				t.Fatalf("size = %d, want exactly %d", len(after), safefile.MaxDotEnvBytes)
			}
			got, err := EnsureGatewayToken(envPath)
			if err != nil || got != want {
				t.Fatalf("token = %q, %v, want %q", got, err, want)
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
				if err := persistRefreshedToken(dir, "adopted-token"); err != nil {
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
					"DEFENSECLAW_GATEWAY_TOKEN=adopted-token",
					"OPENCLAW_GATEWAY_TOKEN=adopted-token",
					envvars.AdoptedGatewayTokenMarker("adopted-token"),
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
				if err != nil || got != "adopted-token" {
					t.Fatalf("token = %q, %v, want the adopted token", got, err)
				}
			})
		}
	}
}
