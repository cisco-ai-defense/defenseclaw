// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisepolicy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The Secure Client guardian publishes the GitHub Copilot drop-in only while
// Copilot is an enabled connector, removes only the one it recorded, and
// never touches a host it did not publish to or the administrator's own
// policy files.
func TestPublishWindowsSecureClientCopilot(t *testing.T) {
	opts := windowsTestOptions(t)
	opts.HookBinary = `C:\Program Files\Cisco\Cisco Secure Client\DefenseClaw\bin\defenseclaw-hook.exe`
	if _, err := PublishWindowsSecureClientCopilot(opts, true); err == nil {
		t.Fatal("published a Secure Client Copilot policy that is not CLI-only")
	}
	opts.CopilotCLIPolicyOnly = true
	dir, err := CopilotPolicyDir(opts)
	if err != nil {
		t.Fatal(err)
	}
	drop := filepath.Join(dir, DefenseClawDropInName)

	// Copilot not enabled and never published: the host is left as found.
	if _, err := PublishWindowsSecureClientCopilot(opts, false); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("a disabled Copilot created %s: %v", dir, err)
	}

	if _, err := PublishWindowsSecureClientCopilot(opts, true); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(drop)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"powershell"`) || !strings.Contains(string(data), `Cisco Secure Client\\DefenseClaw\\bin\\defenseclaw-hook.exe`) {
		t.Fatalf("drop-in does not run the Secure Client hook: %s", data)
	}
	admin := filepath.Join(dir, "10-company.json")
	if err := os.WriteFile(admin, []byte(`{"version": 1, "hooks": {}}`), 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := PublishWindowsSecureClientCopilot(opts, false); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(drop); !os.IsNotExist(err) {
		t.Fatalf("the recorded drop-in survived Copilot being turned off: %v", err)
	}
	if _, err := os.Stat(admin); err != nil {
		t.Fatalf("the administrator's policy file was removed: %v", err)
	}
	// Removal is idempotent once the record is gone.
	if _, err := RemoveWindowsSecureClientCopilot(opts); err != nil {
		t.Fatal(err)
	}
}
