// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func writeEnvConfig(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatalf("write %s: %v", p, err)
	}
	return p
}

func TestLoadEnvConfigEndpointHappyPath(t *testing.T) {
	dir := t.TempDir()
	p := writeEnvConfig(t, dir, "env_config.json",
		`{"cisco_ai_defense_endpoint": "https://eu.api.inspect.aidefense.security.cisco.com"}`)
	got, err := LoadEnvConfigEndpoint(p)
	if err != nil {
		t.Fatalf("LoadEnvConfigEndpoint: %v", err)
	}
	want := "https://eu.api.inspect.aidefense.security.cisco.com"
	if got != want {
		t.Fatalf("endpoint = %q, want %q", got, want)
	}
}

func TestLoadEnvConfigEndpointMissingIsSentinel(t *testing.T) {
	// A missing file MUST return ErrEnvConfigMissing so callers can
	// distinguish "no override" from "override was rejected".
	dir := t.TempDir()
	_, err := LoadEnvConfigEndpoint(filepath.Join(dir, "does-not-exist.json"))
	if !errors.Is(err, ErrEnvConfigMissing) {
		t.Fatalf("err = %v, want ErrEnvConfigMissing", err)
	}
}

func TestLoadEnvConfigEndpointEmptyPathIsSentinel(t *testing.T) {
	// Called with no path (opensource mode passes ""), MUST behave
	// like a missing file — callers unconditionally invoke and check
	// the sentinel.
	_, err := LoadEnvConfigEndpoint("")
	if !errors.Is(err, ErrEnvConfigMissing) {
		t.Fatalf("err = %v, want ErrEnvConfigMissing", err)
	}
}

func TestLoadEnvConfigEndpointRejectsBadJSON(t *testing.T) {
	dir := t.TempDir()
	p := writeEnvConfig(t, dir, "env_config.json", `{not json`)
	got, err := LoadEnvConfigEndpoint(p)
	if err == nil {
		t.Fatalf("LoadEnvConfigEndpoint on malformed JSON returned nil error, got=%q", got)
	}
	if errors.Is(err, ErrEnvConfigMissing) {
		t.Fatalf("malformed JSON must not surface as ErrEnvConfigMissing")
	}
	if got != "" {
		t.Fatalf("endpoint = %q on error, want empty", got)
	}
}

func TestLoadEnvConfigEndpointRejectsMissingKey(t *testing.T) {
	dir := t.TempDir()
	p := writeEnvConfig(t, dir, "env_config.json", `{"other_field": "https://example.test"}`)
	_, err := LoadEnvConfigEndpoint(p)
	if err == nil {
		t.Fatalf("LoadEnvConfigEndpoint with missing key returned nil error")
	}
}

func TestLoadEnvConfigEndpointRejectsNonString(t *testing.T) {
	dir := t.TempDir()
	p := writeEnvConfig(t, dir, "env_config.json", `{"cisco_ai_defense_endpoint": 42}`)
	_, err := LoadEnvConfigEndpoint(p)
	if err == nil {
		t.Fatalf("LoadEnvConfigEndpoint with non-string endpoint returned nil error")
	}
}

func TestLoadEnvConfigEndpointRejectsEmpty(t *testing.T) {
	dir := t.TempDir()
	p := writeEnvConfig(t, dir, "env_config.json", `{"cisco_ai_defense_endpoint": "   "}`)
	_, err := LoadEnvConfigEndpoint(p)
	if err == nil {
		t.Fatalf("LoadEnvConfigEndpoint with whitespace-only endpoint returned nil error")
	}
}

// Table-driven URL rejection cases. Every entry MUST also be rejected
// by _valid_aid_endpoint_url in packaging/macos/lib/installer_lib.sh so
// the shell installer and the Go re-read stay in lockstep. If either
// side loosens its validation the other must follow — a hostile
// env_config that passes one but not the other is precisely the
// security exposure the two-layer validation is designed to prevent.
func TestValidateAIDefenseEndpoint(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want bool // true = accepted
	}{
		{"bare-origin-us", "https://us.api.inspect.aidefense.security.cisco.com", true},
		{"bare-origin-eu-with-port", "https://eu.api.inspect.aidefense.security.cisco.com:443", true},
		{"trailing-slash", "https://us.api.inspect.aidefense.security.cisco.com/", true},

		{"http-rejected", "http://us.api.inspect.aidefense.security.cisco.com", false},
		{"userinfo-rejected", "https://user@us.api.inspect.aidefense.security.cisco.com", false},
		{"userpass-rejected", "https://user:pass@us.api.inspect.aidefense.security.cisco.com", false},
		{"path-rejected", "https://us.api.inspect.aidefense.security.cisco.com/api", false},
		{"query-rejected", "https://us.api.inspect.aidefense.security.cisco.com?x=1", false},
		{"fragment-rejected", "https://us.api.inspect.aidefense.security.cisco.com#x", false},
		{"scheme-only-rejected", "https://", false},
		{"gibberish-rejected", "not-a-url", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateAIDefenseEndpoint(tc.in)
			ok := err == nil
			if ok != tc.want {
				t.Fatalf("validate(%q): got err=%v, want accepted=%v", tc.in, err, tc.want)
			}
		})
	}
}
