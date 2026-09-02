// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package idfabric

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestValidateEmail(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{name: "plain address", input: "dev@example.com", want: "dev@example.com"},
		{name: "surrounding whitespace trimmed", input: "  dev@example.com\n", want: "dev@example.com"},
		{name: "subdomain", input: "a.b+tag@corp.example.co.uk", want: "a.b+tag@corp.example.co.uk"},
		{name: "empty", input: "   ", want: ""},
		{name: "no at sign", input: "devexample.com", want: ""},
		{name: "leading at sign", input: "@example.com", want: ""},
		{name: "trailing at sign", input: "dev@", want: ""},
		{name: "two at signs", input: "dev@a@example.com", want: ""},
		{name: "embedded newline for log injection", input: "dev@example.com\nrole=admin", want: ""},
		{name: "embedded quote breaks JSON framing", input: `dev"@example.com`, want: ""},
		{name: "embedded backslash", input: `dev\@example.com`, want: ""},
		{name: "display name form", input: "Dev <dev@example.com>", want: ""},
		{name: "comma separated list", input: "dev@example.com,other@example.com", want: ""},
		{name: "internal whitespace", input: "dev @example.com", want: ""},
		{name: "non ascii homoglyph", input: "dev@exаmple.com", want: ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := validateEmail(tc.input)
			if tc.want == "" {
				if err == nil {
					t.Fatalf("validateEmail(%q) = %q, want rejection", tc.input, got)
				}
				if !errors.Is(err, ErrNoAttribution) {
					t.Errorf("error = %v, want ErrNoAttribution", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("validateEmail(%q): %v", tc.input, err)
			}
			if got != tc.want {
				t.Errorf("validateEmail(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

// unverifiedTestJWT builds a three-segment token whose payload carries claims.
// The signature segment is a placeholder: this package never verifies it.
func unverifiedTestJWT(t *testing.T, claims map[string]any) string {
	t.Helper()
	body, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	return header + "." + base64.RawURLEncoding.EncodeToString(body) + ".not-a-signature"
}

func TestEmailFromUnverifiedJWT(t *testing.T) {
	t.Run("extracts the email claim", func(t *testing.T) {
		token := unverifiedTestJWT(t, map[string]any{
			"email": "dev@example.com",
			"sub":   "user-123",
		})
		got, ok := emailFromUnverifiedJWT(token)
		if !ok {
			t.Fatal("emailFromUnverifiedJWT reported failure")
		}
		if got != "dev@example.com" {
			t.Errorf("email = %q", got)
		}
	})

	rejects := []struct {
		name  string
		token string
	}{
		{name: "empty", token: ""},
		{name: "not a jwt", token: "opaque-token"},
		{name: "two segments", token: "aaa.bbb"},
		{name: "payload is not base64url", token: "aaa.!!!not-base64!!!.ccc"},
		{name: "payload is not json", token: "aaa." + base64.RawURLEncoding.EncodeToString([]byte("plain")) + ".ccc"},
	}
	for _, tc := range rejects {
		t.Run(tc.name, func(t *testing.T) {
			if got, ok := emailFromUnverifiedJWT(tc.token); ok {
				t.Fatalf("emailFromUnverifiedJWT(%q) = %q, want failure", tc.token, got)
			}
		})
	}

	t.Run("missing email claim", func(t *testing.T) {
		token := unverifiedTestJWT(t, map[string]any{"sub": "user-123"})
		if got, ok := emailFromUnverifiedJWT(token); ok {
			t.Fatalf("got %q, want failure when no email claim is present", got)
		}
	})
}

func TestUserEmailForConnector(t *testing.T) {
	t.Run("claude code reads oauthAccount", func(t *testing.T) {
		home := t.TempDir()
		setHome(t, home)
		t.Setenv("CLAUDE_CONFIG_DIR", "")
		writeJSON(t, filepath.Join(home, ".claude.json"), map[string]any{
			"oauthAccount": map[string]any{"emailAddress": "dev@example.com"},
		})

		got, err := UserEmailForConnector(PlatformClaudeCode, home, nil)
		if err != nil {
			t.Fatalf("UserEmailForConnector: %v", err)
		}
		if got != "dev@example.com" {
			t.Errorf("email = %q", got)
		}
	})

	t.Run("claude code honors CLAUDE_CONFIG_DIR", func(t *testing.T) {
		home := t.TempDir()
		setHome(t, home)
		configDir := filepath.Join(home, "relocated")
		t.Setenv("CLAUDE_CONFIG_DIR", configDir)
		writeJSON(t, filepath.Join(configDir, ".claude.json"), map[string]any{
			"oauthAccount": map[string]any{"emailAddress": "relocated@example.com"},
		})

		got, err := UserEmailForConnector(PlatformClaudeCode, home, nil)
		if err != nil {
			t.Fatalf("UserEmailForConnector: %v", err)
		}
		if got != "relocated@example.com" {
			t.Errorf("email = %q", got)
		}
	})

	t.Run("codex reads the id token claim", func(t *testing.T) {
		home := t.TempDir()
		setHome(t, home)
		codexHome := filepath.Join(home, ".codex")
		t.Setenv("CODEX_HOME", codexHome)
		token := unverifiedTestJWT(t, map[string]any{"email": "codex-user@example.com"})
		writeJSON(t, filepath.Join(codexHome, "auth.json"), map[string]any{
			"tokens": map[string]any{"id_token": token},
		})

		got, err := UserEmailForConnector(PlatformCodex, home, nil)
		if err != nil {
			t.Fatalf("UserEmailForConnector: %v", err)
		}
		if got != "codex-user@example.com" {
			t.Errorf("email = %q", got)
		}
	})

	t.Run("codex without auth file is unavailable not fatal", func(t *testing.T) {
		home := t.TempDir()
		setHome(t, home)
		t.Setenv("CODEX_HOME", filepath.Join(home, ".codex"))

		if _, err := UserEmailForConnector(PlatformCodex, home, nil); !errors.Is(err, ErrNoAttribution) {
			t.Fatalf("error = %v, want ErrNoAttribution", err)
		}
	})

	t.Run("cursor reads the payload field", func(t *testing.T) {
		got, err := UserEmailForConnector(
			PlatformCursor,
			t.TempDir(),
			[]byte(`{"user_email":"cursor-user@example.com"}`),
		)
		if err != nil {
			t.Fatalf("UserEmailForConnector: %v", err)
		}
		if got != "cursor-user@example.com" {
			t.Errorf("email = %q", got)
		}
	})

	t.Run("cursor rejects an unsafe payload value", func(t *testing.T) {
		if _, err := UserEmailForConnector(
			PlatformCursor,
			t.TempDir(),
			[]byte(`{"user_email":"admin@example.com\nsid=S-1-5-18"}`),
		); !errors.Is(err, ErrNoAttribution) {
			t.Fatalf("error = %v, want ErrNoAttribution", err)
		}
	})
}

func TestReadBoundedFileRefusesSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "real.json")
	if err := os.WriteFile(target, []byte(`{}`), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	link := filepath.Join(dir, "link.json")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if _, err := readBoundedFile(link); err == nil {
		t.Fatal("readBoundedFile followed a symlink")
	}
}
