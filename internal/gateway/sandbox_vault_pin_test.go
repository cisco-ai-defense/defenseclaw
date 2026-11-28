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

//go:build !windows

package gateway

import (
	"bytes"
	"crypto/ecdh"
	"crypto/hpke"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/vault"
)

// swapVaultPublicKey rewrites the sealed vault's public key as a process
// that can write the file could.
func swapVaultPublicKey(t *testing.T, path string) {
	t.Helper()
	priv, err := hpke.DHKEM(ecdh.X25519()).GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var f map[string]any
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	h, ok := f["seal"].(map[string]any)
	if !ok {
		t.Fatal("the vault has no seal header")
	}
	h["public_key"] = base64.StdEncoding.EncodeToString(priv.PublicKey().Bytes())
	b, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

// A sealed vault whose header was swapped, or that was replaced with a
// plain one, gets no capture: the prompt is still stopped and the secret
// is not sent on, and the vault file is not changed.
func TestSandboxVaultRefusesCaptureIntoAChangedVault(t *testing.T) {
	for name, tc := range map[string]struct {
		tamper func(t *testing.T, path string)
		says   string
	}{
		"swapped header": {swapVaultPublicKey, "check it with your vault key"},
		"plain vault": {func(t *testing.T, path string) {
			if err := os.WriteFile(path, []byte(`{"version": 1, "entries": []}`), 0o600); err != nil {
				t.Fatal(err)
			}
		}, "seal it again"},
	} {
		tamper := tc.tamper
		t.Run(name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "vault")
			keys := &countingKeys{items: map[string][]byte{}}
			if _, err := vault.OpenWith(dir, keys).Add(vault.AddInput{Name: "OTHER", Value: "value-other", Host: "api.example.com"}); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, vault.FileName)
			tamper(t, path)
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			f := newSandboxIngressFixture(t, withTestVault(vault.Open(dir)))
			key := vaultTestAnthropicKey()
			rec := f.do(t, http.MethodPost, "/api/v1/claude-code/hook", f.claudeTok,
				`{"hook_event_name":"UserPromptSubmit","session_id":"sess-pin","prompt":"use `+key+` now","cwd":"/work/app"}`)
			if rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), key) {
				t.Fatalf("hook: %d", rec.Code)
			}
			var resp map[string]interface{}
			if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil || resp["action"] != "block" {
				t.Fatalf("answer = %v %v", resp, err)
			}
			after, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(before, after) {
				t.Fatal("the capture changed a vault whose seal no longer matches what the gateway pinned")
			}
			if !strings.Contains(rec.Body.String(), "defenseclaw sandbox vault list") {
				t.Fatalf("the answer does not tell the person how to check the vault: %s", rec.Body.String())
			}
			if !strings.Contains(rec.Body.String(), tc.says) {
				t.Fatalf("the answer does not say %q: %s", tc.says, rec.Body.String())
			}
		})
	}
}

// A capture the vault refused because it does not match its pin is
// recorded as a HIGH alert naming the reason; other capture errors are not.
func TestSandboxVaultPinAlert(t *testing.T) {
	for name, tc := range map[string]struct {
		err    error
		reason string
	}{
		"changed": {fmt.Errorf("%w (vault.json)", vault.ErrSealChanged), "seal_changed"},
		"removed": {fmt.Errorf("%w (vault.json)", vault.ErrSealRemoved), "seal_removed"},
		"busy":    {vault.ErrBusy, ""},
	} {
		t.Run(name, func(t *testing.T) {
			store, logger := testStoreAndLogger(t)
			api := &APIServer{store: store, logger: logger}
			api.alertSandboxVaultChanged(t.Context(), "claudecode", &sandboxVaultCapture{Event: "UserPromptSubmit", Sandbox: "demo", Err: tc.err})
			events, err := store.ListEvents(100)
			if err != nil {
				t.Fatal(err)
			}
			alerts := 0
			for _, e := range events {
				if strings.Contains(e.Details, sandboxVaultPinRuleID) {
					alerts++
					if e.Severity != "HIGH" || !strings.Contains(e.Details, tc.reason) {
						t.Fatalf("alert = %+v", e)
					}
				}
			}
			if want := tc.reason != ""; (alerts == 1) != want {
				t.Fatalf("alerts = %d, want alert %v; events %+v", alerts, want, events)
			}
		})
	}
}
