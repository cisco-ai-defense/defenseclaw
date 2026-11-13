// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import (
	"bytes"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/budgetstore"
)

func TestStoreKeyFileHoldsTheAuthKeyOnly(t *testing.T) {
	dir := t.TempDir()
	secret := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{3}, budgetstore.SecretBytes))
	raw := filepath.Join(dir, "secret")
	if err := os.WriteFile(raw, []byte(secret), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readStoreAuthKey(raw); err == nil || !strings.Contains(err.Error(), "not the tenant secret") {
		t.Fatalf("a raw tenant secret must be refused: %v", err)
	}
	keys, _ := budgetstore.DeriveKeys(bytes.Repeat([]byte{3}, budgetstore.SecretBytes))
	authFile := filepath.Join(dir, "auth")
	if err := os.WriteFile(authFile, []byte(budgetstore.AuthKeyPrefix+base64.StdEncoding.EncodeToString(keys.AuthKey())+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readStoreAuthKey(authFile); err != nil {
		t.Fatalf("derive-auth-key output: %v", err)
	}
	if err := os.Chmod(authFile, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readStoreAuthKey(authFile); err == nil || !strings.Contains(err.Error(), "readable by others") {
		t.Fatalf("a world-readable key file must be refused: %v", err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(raw, link); err != nil {
		t.Fatal(err)
	}
	if _, err := readOwnerOnlyFile(link); err == nil {
		t.Fatal("a symlink must be refused")
	}
}
