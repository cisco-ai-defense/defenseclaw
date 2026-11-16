// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// GAP-0490: the gateway refuses to start on an untrusted scanner runtime, so
// a lifecycle action that can start it removes such a tree first; otherwise
// /repair failed at the service start before its scanner step ran.
func TestUntrustedScannerRuntimeIsRetiredBeforeTheServicesStart(t *testing.T) {
	seamDir, seamElevated, seamCheck := windowsScannerRuntimeDir, windowsEnterpriseIsElevated, windowsScannerRuntimeTreeCheck
	t.Cleanup(func() {
		windowsScannerRuntimeDir, windowsEnterpriseIsElevated, windowsScannerRuntimeTreeCheck = seamDir, seamElevated, seamCheck
	})
	untrusted := errors.New("BUILTIN\\Users can add files to the python folder")
	cases := []struct {
		name     string
		action   string
		opts     windowsEnterpriseLifecycleOptions
		elevated bool
		checks   []error
		removed  bool
	}{
		{name: "repair", action: "Repair", elevated: true, checks: []error{untrusted, untrusted}, removed: true},
		{name: "install", action: "Install", elevated: true, checks: []error{untrusted, untrusted}, removed: true},
		{name: "recover", action: "Recover", elevated: true, checks: []error{untrusted, untrusted}, removed: true},
		{name: "trusted", action: "Upgrade", elevated: true, checks: []error{nil}},
		{name: "replaced while waiting", action: "Upgrade", elevated: true, checks: []error{untrusted, nil}},
		{name: "status", action: "Status", elevated: true, checks: []error{untrusted}},
		{name: "standard user", action: "Repair", checks: []error{untrusted}},
		{name: "certification", action: "Repair", elevated: true, opts: windowsEnterpriseLifecycleOptions{allowUnsigned: true}, checks: []error{untrusted}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "DefenseClaw-ScannerRuntime")
			python := filepath.Join(root, "0123", "python")
			if err := os.MkdirAll(python, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(python, "sitecustomize.py"), []byte("planted"), 0o600); err != nil {
				t.Fatal(err)
			}
			windowsScannerRuntimeDir = func() (string, error) { return root, nil }
			windowsEnterpriseIsElevated = func() bool { return tc.elevated }
			checked := 0
			windowsScannerRuntimeTreeCheck = func(got string) error {
				if got != root {
					t.Fatalf("trust check of %s", got)
				}
				if checked >= len(tc.checks) {
					return tc.checks[len(tc.checks)-1]
				}
				checked++
				return tc.checks[checked-1]
			}
			opts := tc.opts
			if err := retireUntrustedWindowsScannerRuntimeBeforeStart(tc.action, &opts); err != nil {
				t.Fatal(err)
			}
			_, statErr := os.Lstat(root)
			if gone := errors.Is(statErr, os.ErrNotExist); gone != tc.removed {
				t.Fatalf("runtime removed=%v (%v), want %v", gone, statErr, tc.removed)
			}
			if (opts.scannerRuntimeRetired != "") != tc.removed {
				t.Fatalf("retired note %q", opts.scannerRuntimeRetired)
			}
			result := enterprisestatus.New("status", managed.ProfileStandalone, "windows", "1.0.4")
			applyWindowsStandaloneScannerRuntime(result, &opts)
			warned := false
			for _, warning := range result.Warnings {
				if warning.Code == "scanner_runtime_untrusted_removed" && strings.Contains(warning.Message, root) {
					warned = true
				}
			}
			if warned != tc.removed {
				t.Fatalf("removal warning=%v, want %v: %+v", warned, tc.removed, result.Warnings)
			}
		})
	}
}
