// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/vault"
)

// countingKeys is an in-memory keystore that counts calls.
type countingKeys struct {
	mu    sync.Mutex
	items map[string][]byte
	calls int
}

func (c *countingKeys) Name() string { return "Secret Service" }
func (c *countingKeys) ID() string   { return "secret-service" }
func (c *countingKeys) Load(id string) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls++
	if c.items[id] == nil {
		return nil, nil
	}
	return append([]byte(nil), c.items[id]...), nil
}

func (c *countingKeys) Save(id string, k []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls++
	c.items[id] = append([]byte(nil), k...)
	return nil
}
func (c *countingKeys) Delete(string) {}

func (c *countingKeys) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.calls
}

// The gateway captures into a vault the CLI sealed with a keystore the
// gateway cannot reach: the hook call never touches the keystore, the
// secret is stored sealed (never in the clear) and the CLI opens it.
func TestSandboxVaultCapturesIntoSealedVaultWithoutKey(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "vault")
	keys := &countingKeys{items: map[string][]byte{}}
	if _, err := vault.OpenWith(dir, keys).Add(vault.AddInput{Name: "OTHER", Value: "value-other", Host: "api.example.com"}); err != nil {
		t.Fatal(err)
	}
	before := keys.count()
	f := newSandboxIngressFixture(t, withTestVault(vault.Open(dir)))
	key := vaultTestAnthropicKey()
	rec := f.do(t, http.MethodPost, "/api/v1/claude-code/hook", f.claudeTok,
		`{"hook_event_name":"UserPromptSubmit","session_id":"sess-seal","prompt":"use `+key+` now","cwd":"/work/app"}`)
	if rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), key) {
		t.Fatalf("hook: %d", rec.Code)
	}
	var resp map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil || resp["action"] != "block" {
		t.Fatalf("answer = %v %v", resp, err)
	}
	if keys.count() != before {
		t.Fatal("the hook call reached the keystore")
	}
	raw, err := os.ReadFile(filepath.Join(dir, vault.FileName))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte(key)) || bytes.Contains(raw, []byte("value-other")) || !bytes.Contains(raw, []byte(`"version": 2`)) {
		t.Fatal("the vault is not sealed after the capture")
	}
	if _, err := vault.OpenWith(dir, keys).Confirm("ANTHROPIC_API_KEY"); err != nil {
		t.Fatal(err)
	}
	if _, v, err := vault.OpenWith(dir, keys).Resolve("ANTHROPIC_API_KEY"); err != nil || v != key {
		t.Fatalf("cli resolve: %v", err)
	}
	if st, _ := vault.Open(dir).Storage(); st.Label != "sealed (Secret Service)" {
		t.Fatalf("storage = %+v", st)
	}
}
