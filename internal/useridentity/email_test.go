// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package useridentity

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// idToken builds an unsigned JWT carrying the given claims. Codex stores a
// real signed token; the reader deliberately does not verify the signature, so
// an unsigned one exercises the same path.
func idToken(t *testing.T, claims map[string]interface{}) string {
	t.Helper()
	body, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	return strings.Join([]string{
		base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`)),
		base64.RawURLEncoding.EncodeToString(body),
		"sig",
	}, ".")
}

func TestClaudeCodeEmailFromProfile(t *testing.T) {
	home := t.TempDir()
	writeFile(t, filepath.Join(home, ".claude.json"), `{"oauthAccount":{"emailAddress":"alice@example.com"},"other":1}`)

	got, err := EmailForConnector("claude-code", home, nil)
	if err != nil || got != "alice@example.com" {
		t.Fatalf("EmailForConnector = (%q, %v), want alice@example.com", got, err)
	}
}

func TestCodexEmailFromIDTokenClaim(t *testing.T) {
	home := t.TempDir()
	token := idToken(t, map[string]interface{}{"email": "bob@example.com", "sub": "abc"})
	writeFile(t, filepath.Join(home, ".codex", "auth.json"), `{"tokens":{"id_token":"`+token+`","access_token":"secret-access"}}`)

	got, err := EmailForConnector("codex", home, nil)
	if err != nil || got != "bob@example.com" {
		t.Fatalf("EmailForConnector = (%q, %v), want bob@example.com", got, err)
	}
}

// TestCodexEmailErrorsNeverCarryTokenBytes matters because auth.json holds live
// credentials, and these errors reach gateway logs.
func TestCodexEmailErrorsNeverCarryTokenBytes(t *testing.T) {
	home := t.TempDir()
	const accessToken = "sk-do-not-log-this"
	// An id_token with no email claim: parses, then fails to yield an address.
	token := idToken(t, map[string]interface{}{"sub": "abc"})
	writeFile(t, filepath.Join(home, ".codex", "auth.json"), `{"tokens":{"id_token":"`+token+`","access_token":"`+accessToken+`"}}`)

	got, err := EmailForConnector("codex", home, nil)
	if got != "" || !errors.Is(err, ErrNoEmail) {
		t.Fatalf("EmailForConnector = (%q, %v), want ErrNoEmail", got, err)
	}
	if msg := err.Error(); strings.Contains(msg, accessToken) || strings.Contains(msg, token) {
		t.Fatalf("error message leaked credential material: %q", msg)
	}
}

func TestCursorEmailComesFromPayloadOnly(t *testing.T) {
	got, err := EmailForConnector("cursor", "", []byte(`{"user_email":"carol@example.com"}`))
	if err != nil || got != "carol@example.com" {
		t.Fatalf("EmailForConnector = (%q, %v), want carol@example.com", got, err)
	}

	// Cursor keeps no local account file, so a profile scan with no payload
	// resolves nothing rather than falling back to some other connector's file.
	home := t.TempDir()
	writeFile(t, filepath.Join(home, ".claude.json"), `{"oauthAccount":{"emailAddress":"alice@example.com"}}`)
	if got, err := EmailForConnector("cursor", home, nil); got != "" || !errors.Is(err, ErrNoEmail) {
		t.Fatalf("cursor profile scan = (%q, %v), want ErrNoEmail", got, err)
	}
}

// TestExplicitHomeIgnoresReaderEnvironmentOverrides is the multi-user
// correctness property. The gateway scans other people's profiles; if
// CODEX_HOME or CLAUDE_CONFIG_DIR from the gateway's own environment were
// honored there, every scanned profile would be attributed to whoever's
// credentials those variables point at.
func TestExplicitHomeIgnoresReaderEnvironmentOverrides(t *testing.T) {
	readerHome := t.TempDir()
	writeFile(t, filepath.Join(readerHome, ".claude.json"), `{"oauthAccount":{"emailAddress":"reader@example.com"}}`)
	writeFile(t, filepath.Join(readerHome, "codex", "auth.json"),
		`{"tokens":{"id_token":"`+idToken(t, map[string]interface{}{"email": "reader@example.com"})+`"}}`)
	t.Setenv("CLAUDE_CONFIG_DIR", readerHome)
	t.Setenv("CODEX_HOME", filepath.Join(readerHome, "codex"))

	scanned := t.TempDir()
	writeFile(t, filepath.Join(scanned, ".claude.json"), `{"oauthAccount":{"emailAddress":"scanned@example.com"}}`)
	writeFile(t, filepath.Join(scanned, ".codex", "auth.json"),
		`{"tokens":{"id_token":"`+idToken(t, map[string]interface{}{"email": "scanned@example.com"})+`"}}`)

	for _, connector := range []string{"claude-code", "codex"} {
		got, err := EmailForConnector(connector, scanned, nil)
		if err != nil {
			t.Fatalf("%s: %v", connector, err)
		}
		if got != "scanned@example.com" {
			t.Fatalf("%s attributed the reader's own account to a scanned profile: %q", connector, got)
		}
	}

	// With no explicit home the overrides are the only way to find the files,
	// so they are honored.
	if got, err := EmailForConnector("claude-code", "", nil); err != nil || got != "reader@example.com" {
		t.Fatalf("ambient claude lookup = (%q, %v), want reader@example.com", got, err)
	}
}

func TestConnectorNameSpellingsFold(t *testing.T) {
	home := t.TempDir()
	writeFile(t, filepath.Join(home, ".claude.json"), `{"oauthAccount":{"emailAddress":"alice@example.com"}}`)
	for _, name := range []string{"claude-code", "claude_code", "ClaudeCode", "  claude  ", "anthropic-claude-code"} {
		if got, err := EmailForConnector(name, home, nil); err != nil || got != "alice@example.com" {
			t.Errorf("EmailForConnector(%q) = (%q, %v)", name, got, err)
		}
	}
	if got, err := EmailForConnector("some-other-agent", home, nil); got != "" || !errors.Is(err, ErrNoEmail) {
		t.Errorf("unknown connector = (%q, %v), want ErrNoEmail", got, err)
	}
}

// TestMalformedAndHostileFilesResolveNothing covers the case that actually
// happens on a real endpoint: any local process running as the user can write
// these files, so every shape of garbage has to end in ErrNoEmail rather than
// a panic, a huge read, or a value that flows into telemetry.
func TestMalformedAndHostileFilesResolveNothing(t *testing.T) {
	for _, tc := range []struct {
		name      string
		connector string
		rel       string
		body      string
	}{
		{"claude not json", "claude-code", ".claude.json", "not json at all"},
		{"claude empty", "claude-code", ".claude.json", ""},
		{"claude wrong shape", "claude-code", ".claude.json", `{"oauthAccount":{"emailAddress":{"nested":true}}}`},
		{"claude missing at", "claude-code", ".claude.json", `{"oauthAccount":{"emailAddress":"alice"}}`},
		{"claude two ats", "claude-code", ".claude.json", `{"oauthAccount":{"emailAddress":"a@b@example.com"}}`},
		{"claude newline injection", "claude-code", ".claude.json", `{"oauthAccount":{"emailAddress":"a@b.com\nX-Injected: 1"}}`},
		{"claude quote injection", "claude-code", ".claude.json", `{"oauthAccount":{"emailAddress":"a\"@b.com"}}`},
		{"claude non-ascii", "claude-code", ".claude.json", `{"oauthAccount":{"emailAddress":"älice@example.com"}}`},
		{"codex not json", "codex", ".codex/auth.json", "{{{"},
		{"codex no tokens", "codex", ".codex/auth.json", `{}`},
		{"codex token not a jwt", "codex", ".codex/auth.json", `{"tokens":{"id_token":"abc"}}`},
		{"codex jwt bad base64", "codex", ".codex/auth.json", `{"tokens":{"id_token":"a.!!!.c"}}`},
		{"codex jwt not json", "codex", ".codex/auth.json",
			`{"tokens":{"id_token":"a.` + base64.RawURLEncoding.EncodeToString([]byte("nope")) + `.c"}}`},
		{"codex empty email claim", "codex", ".codex/auth.json",
			`{"tokens":{"id_token":"a.` + base64.RawURLEncoding.EncodeToString([]byte(`{"email":"  "}`)) + `.c"}}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			writeFile(t, filepath.Join(home, filepath.FromSlash(tc.rel)), tc.body)
			got, err := EmailForConnector(tc.connector, home, nil)
			if got != "" || !errors.Is(err, ErrNoEmail) {
				t.Fatalf("EmailForConnector = (%q, %v), want ErrNoEmail", got, err)
			}
		})
	}
}

func TestOversizeCredentialFileIsRefused(t *testing.T) {
	home := t.TempDir()
	padding := strings.Repeat("p", maxCredentialFileBytes)
	writeFile(t, filepath.Join(home, ".claude.json"),
		`{"pad":"`+padding+`","oauthAccount":{"emailAddress":"alice@example.com"}}`)

	if got, err := EmailForConnector("claude-code", home, nil); got != "" || !errors.Is(err, ErrNoEmail) {
		t.Fatalf("EmailForConnector = (%q, %v), want ErrNoEmail for an oversize file", got, err)
	}
}

// TestSymlinkedCredentialFileIsRefused keeps a profile from redirecting the
// read. Under a managed install the gateway holds more privilege than the
// profile owner, so following a link out of the profile is a read the owner
// could not perform themselves.
func TestSymlinkedCredentialFileIsRefused(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation requires elevation on Windows")
	}
	other := t.TempDir()
	target := filepath.Join(other, "elsewhere.json")
	writeFile(t, target, `{"oauthAccount":{"emailAddress":"victim@example.com"}}`)

	home := t.TempDir()
	if err := os.Symlink(target, filepath.Join(home, ".claude.json")); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	if got, err := EmailForConnector("claude-code", home, nil); got != "" || !errors.Is(err, ErrNoEmail) {
		t.Fatalf("EmailForConnector followed a symlink: (%q, %v)", got, err)
	}
}

func TestValidateEmailBounds(t *testing.T) {
	long := strings.Repeat("a", maxEmailLength) + "@example.com"
	if got, err := validateEmail(long); got != "" || !errors.Is(err, ErrNoEmail) {
		t.Fatalf("validateEmail(oversize) = (%q, %v)", got, err)
	}
	if got, err := validateEmail("  alice@example.com  "); err != nil || got != "alice@example.com" {
		t.Fatalf("validateEmail(padded) = (%q, %v)", got, err)
	}
	if got, err := validateEmail("alice@"); got != "" || !errors.Is(err, ErrNoEmail) {
		t.Fatalf("validateEmail(no domain) = (%q, %v)", got, err)
	}
	if got, err := validateEmail("@example.com"); got != "" || !errors.Is(err, ErrNoEmail) {
		t.Fatalf("validateEmail(no local part) = (%q, %v)", got, err)
	}
}
