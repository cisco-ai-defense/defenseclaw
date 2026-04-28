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
)

func TestEnsureGatewayToken_GeneratesAndPersists(t *testing.T) {
	tmp := t.TempDir()
	dotenv := filepath.Join(tmp, ".env")

	// Process env must not leak into the synthesized value.
	t.Setenv("DEFENSECLAW_GATEWAY_TOKEN", "")
	t.Setenv("OPENCLAW_GATEWAY_TOKEN", "")

	tok, err := EnsureGatewayToken(dotenv)
	if err != nil {
		t.Fatalf("EnsureGatewayToken: %v", err)
	}
	if len(tok) != 64 { // 32-byte hex
		t.Errorf("expected 64-char hex token, got %d chars: %q", len(tok), tok)
	}
	for _, c := range tok {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			t.Errorf("non-hex char %q in token", c)
		}
	}

	info, err := os.Stat(dotenv)
	if err != nil {
		t.Fatalf("stat dotenv: %v", err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Errorf("dotenv mode = %v, want 0o600", mode)
	}

	data, err := os.ReadFile(dotenv)
	if err != nil {
		t.Fatalf("read dotenv: %v", err)
	}
	want := "DEFENSECLAW_GATEWAY_TOKEN=" + tok
	if !strings.Contains(string(data), want) {
		t.Errorf("dotenv missing expected line:\n%s\n---\nwant: %s", data, want)
	}
}

func TestEnsureGatewayToken_Idempotent(t *testing.T) {
	tmp := t.TempDir()
	dotenv := filepath.Join(tmp, ".env")
	t.Setenv("DEFENSECLAW_GATEWAY_TOKEN", "")
	t.Setenv("OPENCLAW_GATEWAY_TOKEN", "")

	first, err := EnsureGatewayToken(dotenv)
	if err != nil {
		t.Fatalf("first call: %v", err)
	}
	second, err := EnsureGatewayToken(dotenv)
	if err != nil {
		t.Fatalf("second call: %v", err)
	}
	if first != second {
		t.Errorf("second call returned different token:\nfirst:  %q\nsecond: %q", first, second)
	}
}

func TestEnsureGatewayToken_PreservesExistingEnvVar(t *testing.T) {
	tmp := t.TempDir()
	dotenv := filepath.Join(tmp, ".env")
	t.Setenv("DEFENSECLAW_GATEWAY_TOKEN", "operator-supplied-token-do-not-overwrite")

	tok, err := EnsureGatewayToken(dotenv)
	if err != nil {
		t.Fatalf("EnsureGatewayToken: %v", err)
	}
	if tok != "operator-supplied-token-do-not-overwrite" {
		t.Errorf("expected to preserve env var, got %q", tok)
	}
	if _, err := os.Stat(dotenv); err == nil {
		t.Error("dotenv should not have been written when env var was already set")
	}
}

func TestEnsureGatewayToken_PreservesOtherDotenvLines(t *testing.T) {
	tmp := t.TempDir()
	dotenv := filepath.Join(tmp, ".env")
	t.Setenv("DEFENSECLAW_GATEWAY_TOKEN", "")
	t.Setenv("OPENCLAW_GATEWAY_TOKEN", "")

	original := "OPENAI_API_KEY=sk-xxx\nANTHROPIC_API_KEY=anth-xxx\n"
	if err := os.WriteFile(dotenv, []byte(original), 0o600); err != nil {
		t.Fatalf("seed dotenv: %v", err)
	}

	if _, err := EnsureGatewayToken(dotenv); err != nil {
		t.Fatalf("EnsureGatewayToken: %v", err)
	}
	data, err := os.ReadFile(dotenv)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	got := string(data)
	if !strings.Contains(got, "OPENAI_API_KEY=sk-xxx") {
		t.Errorf("OPENAI_API_KEY removed:\n%s", got)
	}
	if !strings.Contains(got, "ANTHROPIC_API_KEY=anth-xxx") {
		t.Errorf("ANTHROPIC_API_KEY removed:\n%s", got)
	}
	if !strings.Contains(got, "DEFENSECLAW_GATEWAY_TOKEN=") {
		t.Errorf("token not appended:\n%s", got)
	}
}
