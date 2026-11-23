// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package sandboxcli

import (
	"encoding/json"
	"sync"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/vault"
)

// Tests never reach the OS keystore: the vault is a file unless a test
// gives it a fake keystore.
func init() { openVault = func(dir string) *vault.Store { return vault.OpenWith(dir, nil) } }

// memKeys is an in-memory keystore named like the macOS Keychain.
type memKeys struct {
	mu    sync.Mutex
	items map[string][]byte
}

func (m *memKeys) Name() string { return "macOS Keychain" }
func (m *memKeys) ID() string   { return "macos-keychain" }
func (m *memKeys) Load(id string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.items[id] == nil {
		return nil, nil
	}
	return append([]byte(nil), m.items[id]...), nil
}

func (m *memKeys) Save(id string, k []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.items[id] = append([]byte(nil), k...)
	return nil
}

func (m *memKeys) Delete(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.items, id)
}

type vaultListDoc struct {
	Storage     string           `json:"storage"`
	Sealed      bool             `json:"sealed"`
	StorageNote string           `json:"storage_note"`
	Entries     []map[string]any `json:"entries"`
}

func listJSON(t *testing.T, ta *testApp) vaultListDoc {
	t.Helper()
	ta.out.Reset()
	ta.ok(t, ta.VaultList(OutputJSON))
	var doc vaultListDoc
	if err := json.Unmarshal(ta.out.Bytes(), &doc); err != nil {
		t.Fatalf("json = %s (%v)", ta.output(), err)
	}
	return doc
}

// vault list and --output json say how the vault is kept: a file (and
// why) with no keystore; sealed, naming the keystore, once one works. The
// first change with a keystore seals a file vault and says so.
func TestVaultListShowsStorage(t *testing.T) {
	ta := newTestApp(t, "")
	ta.ReadSecret = func(string) (string, error) { return fakeVaultValue(), nil }
	ta.ok(t, ta.VaultAdd("STRIPE_API_KEY", "api.stripe.com", VaultValueOptions{}))
	has(t, ta.output(), "not encrypted")
	ta.out.Reset()
	ta.ok(t, ta.VaultList(OutputText))
	has(t, ta.output(), "Storage: file (owner-only, not encrypted)")
	if doc := listJSON(t, ta); doc.Storage != vault.StorageFileLabel || doc.Sealed || doc.StorageNote == "" {
		t.Fatalf("json = %+v", doc)
	}

	keys := &memKeys{items: map[string][]byte{}}
	prev := openVault
	openVault = func(dir string) *vault.Store { return vault.OpenWith(dir, keys) }
	t.Cleanup(func() { openVault = prev })
	ta.out.Reset()
	ta.ok(t, ta.VaultBind("STRIPE_API_KEY", "api.stripe.com:443"))
	has(t, ta.output(), "now sealed", "macOS Keychain")
	ta.out.Reset()
	ta.ok(t, ta.VaultList(OutputText))
	has(t, ta.output(), "Storage: sealed (macOS Keychain)", "STRIPE_API_KEY")
	doc := listJSON(t, ta)
	if doc.Storage != "sealed (macOS Keychain)" || !doc.Sealed || len(doc.Entries) != 1 {
		t.Fatalf("json = %+v", doc)
	}
	if _, v, err := vault.OpenWith(ta.VaultDir(), keys).Resolve("STRIPE_API_KEY"); err != nil || v != fakeVaultValue() {
		t.Fatalf("resolve = %v", err)
	}
	lacks(t, ta.output()+ta.err.String(), fakeVaultValue())
}
