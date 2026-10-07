// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"

	"github.com/defenseclaw/defenseclaw/internal/config/configwrite"
)

// An uninstall that keeps state leaves config.generation.json
// administrator-only. Installing the same config again gives the record the
// config's DACL back, so the gateway service can read its generation
// (GAP-0293).
func TestMigrateManagedStandaloneConfigRestoresTheRecordDACL(t *testing.T) {
	t.Setenv("DEFENSECLAW_DEPLOYMENT_MODE", "")
	t.Setenv("DEFENSECLAW_ENTERPRISE_PROFILE", "")
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("config_version: 9\nobservability: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := migrateManagedStandaloneConfig(context.Background(), path); err != nil {
		t.Fatal(err)
	}
	record := configwrite.GenerationPath(path)
	setDACL := func(target, sddl string) {
		t.Helper()
		sd, err := windows.SecurityDescriptorFromString(sddl)
		if err != nil {
			t.Fatal(err)
		}
		dacl, _, err := sd.DACL()
		if err != nil {
			t.Fatal(err)
		}
		if err := windows.SetNamedSecurityInfo(target, windows.SE_FILE_OBJECT,
			windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
			t.Fatal(err)
		}
	}
	readDACL := func(target string) string {
		t.Helper()
		sd, err := windows.GetNamedSecurityInfo(target, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
		if err != nil {
			t.Fatal(err)
		}
		return sd.String()
	}
	setDACL(path, "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;OW)(A;;FR;;;WD)")
	setDACL(record, "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;OW)")
	if err := migrateManagedStandaloneConfig(context.Background(), path); err != nil {
		t.Fatal(err)
	}
	if got, want := readDACL(record), readDACL(path); got != want {
		t.Fatalf("config.generation.json DACL = %s, want the config DACL %s", got, want)
	}
}

// An inline scanner key rewrites .env during a v8 upgrade. The secret file
// keeps its own private DACL even when config.yaml is readable by Users.
func TestMigrateManagedStandaloneConfigKeepsDotEnvDACL(t *testing.T) {
	t.Setenv("DEFENSECLAW_DEPLOYMENT_MODE", "")
	t.Setenv("DEFENSECLAW_ENTERPRISE_PROFILE", "")
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	envPath := filepath.Join(dir, ".env")
	v8 := "config_version: 8\ndata_dir: " + dir +
		"\nscanners:\n  skill_scanner:\n    use_virustotal: true\n    virustotal_api_key: vt-test-value\nobservability: {}\n"
	if err := os.WriteFile(path, []byte(v8), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(envPath, []byte("GATEWAY_TOKEN=existing\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	setDACL := func(target, sddl string) {
		t.Helper()
		sd, err := windows.SecurityDescriptorFromString(sddl)
		if err != nil {
			t.Fatal(err)
		}
		dacl, _, err := sd.DACL()
		if err != nil {
			t.Fatal(err)
		}
		if err := windows.SetNamedSecurityInfo(target, windows.SE_FILE_OBJECT,
			windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
			nil, nil, dacl, nil); err != nil {
			t.Fatal(err)
		}
	}
	readDACL := func(target string) string {
		t.Helper()
		sd, err := windows.GetNamedSecurityInfo(target, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
		if err != nil {
			t.Fatal(err)
		}
		return sd.String()
	}
	setDACL(path, "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;OW)(A;;FR;;;BU)")
	setDACL(envPath, "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;OW)")
	before := readDACL(envPath)
	if err := migrateManagedStandaloneConfig(context.Background(), path); err != nil {
		t.Fatal(err)
	}
	if got := readDACL(envPath); got != before {
		t.Fatalf(".env DACL changed: before %s, after %s", before, got)
	}
}
