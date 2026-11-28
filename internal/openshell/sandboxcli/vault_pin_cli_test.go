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

package sandboxcli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/vault"
)

// vault list says when the vault does not match the seal the gateway
// pinned, and fixes what it can with the key: a damaged pin is renewed, a
// sealed vault replaced with a plain one is sealed again. Without a
// keystore it warns, and --output json carries the pin state.
func TestVaultListChecksThePin(t *testing.T) {
	ta := newTestApp(t, "")
	keys := &memKeys{items: map[string][]byte{}}
	prev := openVault
	openVault = func(dir string) *vault.Store { return vault.OpenWith(dir, keys) }
	t.Cleanup(func() { openVault = prev })
	ta.ReadSecret = func(string) (string, error) { return fakeVaultValue(), nil }
	ta.ok(t, ta.VaultAdd("STRIPE_API_KEY", "api.stripe.com", VaultValueOptions{}))
	pin := filepath.Join(filepath.Dir(ta.VaultDir()), vault.PinFileName)
	if _, err := os.Stat(pin); err != nil {
		t.Fatalf("the seal was not pinned: %v", err)
	}

	if err := os.WriteFile(pin, []byte("not a pin"), 0o600); err != nil {
		t.Fatal(err)
	}
	ta.out.Reset()
	ta.ok(t, ta.VaultList(OutputText))
	has(t, ta.output(), "pinned again", "Storage: sealed (macOS Keychain)")

	vaultFile := filepath.Join(ta.VaultDir(), vault.FileName)
	plain := []byte(`{"version": 1, "entries": []}`)
	if err := os.WriteFile(vaultFile, plain, 0o600); err != nil {
		t.Fatal(err)
	}
	openVault = func(dir string) *vault.Store { return vault.OpenWith(dir, nil) }
	ta.out.Reset()
	ta.ok(t, ta.VaultList(OutputJSON))
	var doc map[string]any
	if err := json.Unmarshal(ta.out.Bytes(), &doc); err != nil {
		t.Fatalf("json = %s (%v)", ta.output(), err)
	}
	if doc["pin"] != "unsealed" || doc["pin_warning"] == nil {
		t.Fatalf("json = %v", doc)
	}

	openVault = func(dir string) *vault.Store { return vault.OpenWith(dir, keys) }
	ta.out.Reset()
	ta.ok(t, ta.VaultList(OutputText))
	has(t, ta.output(), "sealed again", "Storage: sealed (macOS Keychain)")
	lacks(t, ta.output()+ta.err.String(), fakeVaultValue())
}
