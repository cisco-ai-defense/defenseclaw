// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

func TestOpenCodeSetupRejectsReparsePluginDirectory(t *testing.T) {
	root := t.TempDir()
	operatorRoot := filepath.Join(root, "operator-owned")
	if err := os.MkdirAll(operatorRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	redirect := filepath.Join(root, "redirect")
	createTestDirectoryRedirect(t, redirect, operatorRoot)

	pluginPath := filepath.Join(redirect, "plugins", "defenseclaw.js")
	previous := OpenCodePluginPathOverride
	OpenCodePluginPathOverride = pluginPath
	t.Cleanup(func() { OpenCodePluginPathOverride = previous })

	err := NewOpenCodeConnector().Setup(context.Background(), SetupOpts{
		DataDir:  filepath.Join(root, "defenseclaw-data"),
		APIAddr:  "127.0.0.1:18970",
		APIToken: "synthetic OpenCode test token",
	})
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "reparse") {
		t.Fatalf("Setup through directory redirect error = %v, want reparse rejection", err)
	}
	if _, statErr := os.Lstat(filepath.Join(operatorRoot, "plugins", "defenseclaw.js")); !os.IsNotExist(statErr) {
		t.Fatalf("rejected Setup wrote through the directory redirect: %v", statErr)
	}
}

func TestOpenCodeSetupPublishesPrivatePluginOverRepairableReadACL(t *testing.T) {
	root := t.TempDir()
	pluginPath := filepath.Join(root, "OpenCode Config", "plugins", "defenseclaw.js")
	if err := os.MkdirAll(filepath.Dir(pluginPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := safefile.ProtectDirectory(filepath.Dir(pluginPath)); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pluginPath, []byte("// operator plugin fixture\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := setAtomicFileUnsafeReadDACL(pluginPath); err != nil {
		t.Fatal(err)
	}
	if err := safefile.ValidatePrivateFile(pluginPath); err == nil {
		t.Fatal("readable-by-Everyone fixture unexpectedly satisfied the private-file contract")
	}

	previous := OpenCodePluginPathOverride
	OpenCodePluginPathOverride = pluginPath
	t.Cleanup(func() { OpenCodePluginPathOverride = previous })
	conn := NewOpenCodeConnector()
	opts := SetupOpts{
		DataDir:  filepath.Join(root, "defenseclaw-data"),
		APIAddr:  "127.0.0.1:18970",
		APIToken: "synthetic OpenCode test token",
	}
	if err := conn.Setup(context.Background(), opts); err != nil {
		t.Fatalf("Setup over repairable read ACL: %v", err)
	}
	if err := safefile.ValidatePrivateFile(pluginPath); err != nil {
		t.Fatalf("Setup did not publish a private managed plugin: %v", err)
	}
	present, err := OwnedHooksPresent(conn, opts)
	if err != nil || !present {
		t.Fatalf("OwnedHooksPresent after private publication = %v, %v", present, err)
	}
}
