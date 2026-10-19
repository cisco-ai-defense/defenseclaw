// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/managed"
	"golang.org/x/sys/windows"
)

func TestSandboxWindowsPersonalConfigRequiresAbsentOrTrustedUninstallRecord(t *testing.T) {
	previous := managedHostRecordTrusted
	t.Cleanup(func() { managedHostRecordTrusted = previous })
	for _, profile := range []string{managed.ProfileStandalone, managed.ProfileSecureClient} {
		for _, test := range []struct {
			name, body            string
			absent, trusted, want bool
		}{
			{name: "absent", absent: true, want: true},
			{name: "trusted uninstall", body: `{"installed":false}`, trusted: true, want: true},
			{name: "installed", body: `{"installed":true}`, trusted: true},
			{name: "unknown malformed", body: `{fixed invalid`, trusted: true},
			{name: "unconfirmed installed", body: `{"installed":true}`},
			{name: "untrusted uninstall", body: `{"installed":false}`},
		} {
			t.Run(profile+"/"+test.name, func(t *testing.T) {
				path := filepath.Join(t.TempDir(), "deployment.json")
				if !test.absent {
					if err := os.WriteFile(path, []byte(test.body), 0o600); err != nil {
						t.Fatal(err)
					}
				}
				trustChecks := 0
				managedHostRecordTrusted = func(candidate string) error {
					trustChecks++
					if candidate != path || !test.trusted {
						return errors.New("fixed untrusted deployment record")
					}
					return nil
				}
				if got := sandboxWindowsPersonalConfigPermittedAt(profile, path); got != test.want {
					t.Fatalf("personal config permitted = %t, want %t", got, test.want)
				}
				if test.absent && trustChecks != 0 || !test.absent && trustChecks != 1 {
					t.Fatalf("unexpected trust checks: %d", trustChecks)
				}
			})
		}
	}
	if sandboxWindowsPersonalConfigPermittedAt(managed.ProfileStandalone, t.TempDir()) {
		t.Fatal("non-regular metadata permitted personal config")
	}
}

func TestSandboxWindowsConfigMarkerAndStateRequireAbsence(t *testing.T) {
	for _, test := range []struct {
		err  error
		want bool
	}{
		{windows.ERROR_FILE_NOT_FOUND, true},
		{windows.ERROR_PATH_NOT_FOUND, true},
		{nil, false},
		{windows.ERROR_ACCESS_DENIED, false},
		{windows.ERROR_INVALID_DATA, false},
		{errors.New("fixed uncertain marker"), false},
	} {
		if sandboxWindowsRegistryPathAbsent(test.err) != test.want {
			t.Fatalf("marker error %v did not preserve absence-only admission", test.err)
		}
	}
	root := t.TempDir()
	if sandboxWindowsStateRootAbsent(root) {
		t.Fatal("existing state root counted as absent")
	}
	if !sandboxWindowsStateRootAbsent(filepath.Join(root, "fixed-absent-root")) {
		t.Fatal("absent state root was refused")
	}
}
