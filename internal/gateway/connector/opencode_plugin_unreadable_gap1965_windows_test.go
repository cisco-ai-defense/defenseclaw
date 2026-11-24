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
	"time"

	"golang.org/x/sys/windows"

	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

// GAP-1965: an OpenCode plugin folder whose inheritance is removed and whose
// access list is empty passes the custody check (no other account can write
// it), but this account cannot open it either. Setup failed only at the
// write with "open private staging directory: Access is denied", which named
// no folder, and that error read as a busy file, so the gateway retried it.
// Setup must refuse before it changes anything, name the folder and the fix,
// and not be retried as a busy file. Run with a Limited token: an elevated
// one lists the folder through its backup privilege.
func TestGAP1965OpenCodeSetupRefusesAnUnreadablePluginFolderPromptly(t *testing.T) {
	dir := testenv.PrivateTempDir(t)
	plugins := filepath.Join(dir, ".config", "opencode", "plugins")
	if err := os.MkdirAll(plugins, 0o700); err != nil {
		t.Fatal(err)
	}
	pluginPath := filepath.Join(plugins, "defenseclaw.js")
	prev := OpenCodePluginPathOverride
	OpenCodePluginPathOverride = pluginPath
	t.Cleanup(func() { OpenCodePluginPathOverride = prev })

	empty, err := windows.SecurityDescriptorFromString("D:PAI")
	if err != nil {
		t.Fatal(err)
	}
	emptyDACL, _, err := empty.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(plugins, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, emptyDACL, nil); err != nil {
		t.Fatalf("empty the plugin folder DACL: %v", err)
	}
	t.Cleanup(func() {
		open, _ := windows.SecurityDescriptorFromString("D:(A;OICI;FA;;;OW)(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)")
		openDACL, _, _ := open.DACL()
		_ = windows.SetNamedSecurityInfo(plugins, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION, nil, nil, openDACL, nil)
	})
	if _, err := os.ReadDir(plugins); err == nil {
		t.Skip("fixture: this token still lists the folder with an empty DACL (backup privilege enabled)")
	}

	opts := prepareOpenCodeSetupOptsForTest(t, SetupOpts{
		DataDir:      filepath.Join(dir, "dc"),
		APIAddr:      "127.0.0.1:18970",
		APIToken:     "tok-opencode-1965",
		HookFailMode: "closed",
	})
	start := time.Now()
	err = NewOpenCodeConnector().Setup(context.Background(), opts)
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("setup succeeded under a plugin folder it cannot open")
	}
	if elapsed > 20*time.Second {
		t.Fatalf("setup took %s to refuse: %v", elapsed, err)
	}
	if !strings.Contains(err.Error(), plugins) || !strings.Contains(err.Error(), "cannot be opened") ||
		!strings.Contains(err.Error(), "icacls") {
		t.Fatalf("the refusal does not name the plugin folder and the fix: %v", err)
	}
	if FileBusyError(err) {
		t.Fatalf("the refusal reads as a busy settings file, so the gateway retries it: %v", err)
	}
	if _, statErr := os.Lstat(managedFileBackupPath(opts.DataDir, "opencode", "config")); statErr == nil {
		t.Fatal("setup wrote the plugin backup receipt before it refused")
	}
}
