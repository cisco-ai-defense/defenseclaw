// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEnsureOTLPPathToken_CreatesAndPersists(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()

	tok, err := EnsureOTLPPathToken(tmp, OTLPScopeGeminiCLI)
	if err != nil {
		t.Fatalf("EnsureOTLPPathToken: %v", err)
	}
	if len(tok) != 64 {
		t.Fatalf("token length = %d, want 64 hex chars", len(tok))
	}
	if strings.ContainsAny(tok, " \t\n") {
		t.Fatalf("token contains whitespace: %q", tok)
	}

	tokenPath, err := OTLPPathTokenFilePath(tmp, OTLPScopeGeminiCLI)
	if err != nil {
		t.Fatalf("OTLPPathTokenFilePath: %v", err)
	}
	info, err := os.Stat(tokenPath)
	if err != nil {
		t.Fatalf("stat token file: %v", err)
	}
	// Token file MUST be owner-only; it grants OTLP ingest privilege
	// to anything that can read it (loopback path-token branch in
	// tokenAuth).
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Fatalf("token file mode = %v, want 0o600", mode)
	}
}

func TestEnsureOTLPPathToken_Idempotent(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()

	first, err := EnsureOTLPPathToken(tmp, OTLPScopeGeminiCLI)
	if err != nil {
		t.Fatalf("first call: %v", err)
	}
	second, err := EnsureOTLPPathToken(tmp, OTLPScopeGeminiCLI)
	if err != nil {
		t.Fatalf("second call: %v", err)
	}
	if first != second {
		t.Fatalf("token rotated unexpectedly: first=%q second=%q", first, second)
	}
}

func TestEnsureOTLPPathToken_RejectsInvalidScope(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()

	for _, scope := range []OTLPPathTokenScope{
		"",
		"unknown",
		"../escape",
		"geminicli/extra",
	} {
		if _, err := EnsureOTLPPathToken(tmp, scope); err == nil {
			t.Fatalf("EnsureOTLPPathToken(%q) accepted invalid scope", scope)
		}
	}
}

func TestEnsureOTLPPathToken_RejectsEmptyDataDir(t *testing.T) {
	t.Parallel()
	if _, err := EnsureOTLPPathToken("", OTLPScopeGeminiCLI); err == nil {
		t.Fatalf("EnsureOTLPPathToken with empty dataDir succeeded; want error to avoid transient tokens")
	}
}

func TestLoadOTLPPathToken_AbsentReturnsEmpty(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	tok, err := LoadOTLPPathToken(tmp, OTLPScopeGeminiCLI)
	if err != nil {
		t.Fatalf("LoadOTLPPathToken: %v", err)
	}
	if tok != "" {
		t.Fatalf("expected empty token for unprovisioned scope, got %q", tok)
	}
}

func TestLoadAllOTLPPathTokens_PicksUpMintedScopes(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()

	minted, err := EnsureOTLPPathToken(tmp, OTLPScopeGeminiCLI)
	if err != nil {
		t.Fatalf("EnsureOTLPPathToken: %v", err)
	}

	all, err := LoadAllOTLPPathTokens(tmp)
	if err != nil {
		t.Fatalf("LoadAllOTLPPathTokens: %v", err)
	}
	if got := all[OTLPScopeGeminiCLI]; got != minted {
		t.Fatalf("LoadAllOTLPPathTokens[geminicli] = %q, want minted token %q", got, minted)
	}
}

func TestEnsureOTLPPathToken_NotMasterTokenLeak(t *testing.T) {
	t.Parallel()
	// Regression: the scoped-token file MUST contain only the scoped
	// token bytes — no Bearer prefix, no API token leakage. This
	// pins the contract that tokenAuth's per-source comparison
	// happens against the raw on-disk bytes.
	tmp := t.TempDir()
	tok, err := EnsureOTLPPathToken(tmp, OTLPScopeGeminiCLI)
	if err != nil {
		t.Fatalf("EnsureOTLPPathToken: %v", err)
	}

	tokenPath, _ := OTLPPathTokenFilePath(tmp, OTLPScopeGeminiCLI)
	data, err := os.ReadFile(tokenPath)
	if err != nil {
		t.Fatalf("read token file: %v", err)
	}
	got := strings.TrimSpace(string(data))
	if got != tok {
		t.Fatalf("on-disk token %q != returned token %q", got, tok)
	}
	if strings.HasPrefix(got, "Bearer ") {
		t.Fatalf("on-disk token starts with Bearer prefix: %q", got)
	}
}

func TestPatchGeminiTelemetry_UsesScopedToken(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	settingsPath := filepath.Join(tmp, "settings.json")
	if err := os.WriteFile(settingsPath, []byte("{}"), 0o600); err != nil {
		t.Fatalf("seed settings.json: %v", err)
	}

	const masterToken = "MASTER-BEARER-DO-NOT-LEAK"
	opts := SetupOpts{
		DataDir:  tmp,
		APIAddr:  "127.0.0.1:18970",
		APIToken: masterToken,
	}

	if err := patchGeminiTelemetry(settingsPath, opts); err != nil {
		t.Fatalf("patchGeminiTelemetry: %v", err)
	}

	body, err := os.ReadFile(settingsPath)
	if err != nil {
		t.Fatalf("read settings.json: %v", err)
	}
	text := string(body)
	if strings.Contains(text, masterToken) {
		t.Fatalf("settings.json contains MASTER bearer token — H4 regression!\n%s", text)
	}

	scoped, err := LoadOTLPPathToken(tmp, OTLPScopeGeminiCLI)
	if err != nil {
		t.Fatalf("LoadOTLPPathToken: %v", err)
	}
	if scoped == "" {
		t.Fatalf("expected scoped OTLP token to be minted by patchGeminiTelemetry")
	}
	if !strings.Contains(text, "/otlp/geminicli/"+scoped) {
		t.Fatalf("settings.json missing scoped token in OTLP endpoint:\n%s", text)
	}
}
