// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/testenv"
	"golang.org/x/sys/windows"
)

// rel-1-0-10:GAP-1097. A managed Windows data dir keeps the DACL the service
// converged: OWNER RIGHTS READ_CONTROL takes the owner's implicit WRITE_DAC,
// the user may modify, SYSTEM and Administrators hold full control. The
// guardian renders route-only as the target (impersonated). The render used
// the data dir as its compare-and-swap state dir and wrote its route record
// with the generic private writer; both re-protect the directory under the
// target's token, which is refused ("prepare stable compare-and-swap
// transaction directory: Access is denied") or, for an elevated token,
// rewrites the managed DACL. The render must succeed and leave it as it was.
func TestManagedWindowsRouteOnlyKeepsTheManagedDataDirDACL(t *testing.T) {
	for _, tc := range []struct {
		name     string
		leaf     string
		original string
		conn     RouteOnlyConnector
		override *string
	}{
		{"claudecode", "settings.json", "{\n  \"model\": \"sonnet\"\n}", NewClaudeCodeConnector(), &ClaudeCodeSettingsPathOverride},
		{"codex", "config.toml", "model = \"gpt-5\"\n", NewCodexConnector(), &CodexConfigPathOverride},
	} {
		t.Run(tc.name, func(t *testing.T) {
			agentPath := filepath.Join(testenv.PrivateTempDir(t), tc.leaf)
			if err := os.WriteFile(agentPath, []byte(tc.original), 0o600); err != nil {
				t.Fatal(err)
			}
			prev := *tc.override
			*tc.override = agentPath
			t.Cleanup(func() { *tc.override = prev })

			user := windowsProcessUserSIDForTest(t)
			dataDir := filepath.Join(testenv.PrivateTempDir(t), ".defenseclaw")
			if err := os.Mkdir(dataDir, 0o700); err != nil {
				t.Fatal(err)
			}
			setManagedWindowsDataDirDACLForTest(t, dataDir, user)
			before := windowsSecurityDescriptorStringForTest(t, dataDir)

			opts := SetupOpts{DataDir: dataDir, ManagedEnterprise: true}
			route := &RouteOnlySetup{BaseURL: "http://127.0.0.1:18970/r/" + tc.name, Token: "dcr1-gap1097"}
			if err := runImpersonatedAsSelfForTest(func() error { return tc.conn.ApplyRouteOnly(opts, route) }); err != nil {
				t.Fatalf("managed route-only render: %v", err)
			}
			if raw, _ := os.ReadFile(agentPath); !bytes.Contains(raw, []byte("/r/"+tc.name)) {
				t.Fatalf("agent config has no route-only render:\n%s", raw)
			}
			record := routeBackupPath(dataDir, tc.name)
			raw, err := os.ReadFile(record)
			if err != nil {
				t.Fatalf("route record: %v", err)
			}
			file := openManagedTargetRuntimeFileForTest(t, record)
			err = validateWindowsManagedTargetRuntimeHandle(file, user, raw)
			_ = file.Close()
			if err != nil {
				t.Fatalf("route record is not in the target-owned managed form: %v", err)
			}
			if after := windowsSecurityDescriptorStringForTest(t, dataDir); after != before {
				t.Fatalf("route-only render changed the managed data dir DACL:\nbefore %s\nafter  %s", before, after)
			}

			if err := runImpersonatedAsSelfForTest(func() error { return tc.conn.ApplyRouteOnly(opts, nil) }); err != nil {
				t.Fatalf("managed route-only restore: %v", err)
			}
			if raw, _ := os.ReadFile(agentPath); string(raw) != tc.original {
				t.Fatalf("restore is not byte exact:\n%q\nwant %q", raw, tc.original)
			}
			if _, err := os.Stat(record); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("route record left after restore: %v", err)
			}
			if after := windowsSecurityDescriptorStringForTest(t, dataDir); after != before {
				t.Fatalf("route-only restore changed the managed data dir DACL:\nbefore %s\nafter  %s", before, after)
			}
		})
	}
}

// setManagedWindowsDataDirDACLForTest gives dir the target-owned managed data
// dir descriptor seen on an enrolled account (rel-1-0-10:GAP-1097 evidence).
func setManagedWindowsDataDirDACLForTest(t *testing.T, dir string, user *windows.SID) {
	t.Helper()
	sd, err := windows.SecurityDescriptorFromString(fmt.Sprintf(
		"D:P(A;;RC;;;OW)(A;;0x1301ff;;;%[1]s)(A;OICIIO;0x1301ff;;;%[1]s)(A;;FA;;;SY)(A;OICIIO;FA;;;SY)(A;;FA;;;BA)(A;OICIIO;FA;;;BA)",
		user.String(),
	))
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		user, nil, dacl, nil); err != nil {
		t.Fatalf("set managed data dir descriptor: %v", err)
	}
}

func windowsSecurityDescriptorStringForTest(t *testing.T, path string) string {
	t.Helper()
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatalf("read descriptor: %v", err)
	}
	return sd.String()
}

// runImpersonatedAsSelfForTest runs fn under a thread token of the process
// user, the shape of the guardian's write as the target.
func runImpersonatedAsSelfForTest(fn func() error) (result error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := windows.ImpersonateSelf(windows.SecurityImpersonation); err != nil {
		return fmt.Errorf("impersonate self: %w", err)
	}
	defer func() {
		if err := windows.RevertToSelf(); err != nil {
			result = errors.Join(result, fmt.Errorf("revert to self: %w", err))
		}
	}()
	return fn()
}
