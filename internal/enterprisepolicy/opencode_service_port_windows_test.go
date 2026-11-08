//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

// requireOpenCodeServiceFilePrivate is the private-file contract of the
// platform: Windows has no POSIX mode, so the file must carry the
// account-private owner and DACL the protected writer gives it.
func requireOpenCodeServiceFilePrivate(t *testing.T, path string) {
	t.Helper()
	if err := safefile.ValidatePrivateFile(path); err != nil {
		t.Fatalf("service.json is not account-private: %v", err)
	}
}

func TestManagedWindowsOpenCodePortWriteIsAccountPrivate(t *testing.T) {
	home := t.TempDir()
	path := OpenCodeServiceConfigPath(home)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(`{"password":"kept"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := SetOpenCodeServicePort(home, 25001)
	if err != nil || !result.Changed || result.Port != 25001 {
		t.Fatalf("write port: %+v %v", result, err)
	}
	if err := safefile.ValidatePrivateFile(path); err != nil {
		t.Fatalf("service.json is not account-private: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil || doc["password"] != "kept" || doc["port"] != float64(25001) {
		t.Fatalf("service.json content: %s, %v", data, err)
	}
	result, err = SetOpenCodeServicePort(home, 25002)
	if err != nil || !result.Changed || result.Port != 25002 {
		t.Fatalf("replace conflicting port: %+v %v", result, err)
	}
	if err := safefile.ValidatePrivateFile(path); err != nil {
		t.Fatalf("replaced service.json is not account-private: %v", err)
	}
	if got, err := ReadOpenCodeServicePortAsUser(home); err != nil || got != 25002 {
		t.Fatalf("replaced service.json port = %d, err=%v", got, err)
	}
}

func TestManagedWindowsOpenCodePortReadSeesAccountLinkedFolder(t *testing.T) {
	home := t.TempDir()
	config := filepath.Join(home, ".config")
	if err := os.MkdirAll(filepath.Join(config, "opencode"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(OpenCodeServiceConfigPath(home), []byte(`{"port":25001}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := ReadOpenCodeServicePortAsUser(home); err != nil || got != 25001 {
		t.Fatalf("regular folder port = %d, err=%v", got, err)
	}
	target := filepath.Join(home, "held-config")
	if err := os.Rename(config, target); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, config); err != nil {
		t.Skipf("this Windows runner cannot create a directory link: %v", err)
	}
	if got, err := ReadOpenCodeServicePortAsUser(home); err != nil || got != 25001 {
		t.Fatalf("account-linked folder port = %d, err=%v", got, err)
	}
	if _, err := SetOpenCodeServicePort(home, 25002); err == nil {
		t.Fatal("linked account folder was changed through the protected writer")
	}
}
