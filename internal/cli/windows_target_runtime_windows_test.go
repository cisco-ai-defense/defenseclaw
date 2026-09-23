//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"golang.org/x/sys/windows"
)

func TestWindowsTargetRuntimeProtectedPathRequiresBothTrustContracts(t *testing.T) {
	originalTrust := windowsTargetRuntimeRequestTrust
	originalAdmin := windowsTargetRuntimeAdminValidate
	t.Cleanup(func() {
		windowsTargetRuntimeRequestTrust = originalTrust
		windowsTargetRuntimeAdminValidate = originalAdmin
	})

	path := filepath.Join(t.TempDir(), "request.json")
	if err := os.WriteFile(path, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	trustCalls := 0
	adminCalls := 0
	windowsTargetRuntimeRequestTrust = func(got, label string) error {
		trustCalls++
		if got != path || label != "target-runtime request" {
			t.Fatalf("trust validation got path=%q label=%q", got, label)
		}
		return nil
	}
	windowsTargetRuntimeAdminValidate = func(got string) error {
		adminCalls++
		if got != path {
			t.Fatalf("AdminFile validation got %q", got)
		}
		return nil
	}
	got, err := requireWindowsTargetRuntimeProtectedPath(path, "target-runtime request")
	if err != nil || got != path || trustCalls != 1 || adminCalls != 1 {
		t.Fatalf("protected path got=%q err=%v trust=%d admin=%d", got, err, trustCalls, adminCalls)
	}

	if _, err := requireWindowsTargetRuntimeProtectedPath("request.json", "target-runtime request"); err == nil {
		t.Fatal("relative protected request path was accepted")
	}
	windowsTargetRuntimeAdminValidate = func(string) error { return errors.New("noncanonical AdminFile") }
	if _, err := requireWindowsTargetRuntimeProtectedPath(path, "target-runtime request"); err == nil || !strings.Contains(err.Error(), "noncanonical AdminFile") {
		t.Fatalf("AdminFile rejection was not propagated: %v", err)
	}
}

func TestWindowsTargetRuntimeProtectedJSONRejectsUnknownAndTrailingDocuments(t *testing.T) {
	originalTrust := windowsTargetRuntimeRequestTrust
	originalAdmin := windowsTargetRuntimeAdminValidate
	windowsTargetRuntimeRequestTrust = func(string, string) error { return nil }
	windowsTargetRuntimeAdminValidate = func(string) error { return nil }
	t.Cleanup(func() {
		windowsTargetRuntimeRequestTrust = originalTrust
		windowsTargetRuntimeAdminValidate = originalAdmin
	})

	for name, data := range map[string]string{
		"unknown":  `{"schema_version":1,"unknown":true}`,
		"trailing": `{"schema_version":1} {"schema_version":1}`,
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "request.json")
			if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
				t.Fatal(err)
			}
			var plan enterprisehooks.WindowsManagedRuntimePlan
			if err := readWindowsTargetRuntimeProtectedJSON(path, &plan); err == nil {
				t.Fatalf("accepted %s protected JSON", name)
			}
		})
	}
}

func TestWindowsTargetRuntimeOutputValidationPrecedesOverwrite(t *testing.T) {
	originalTrust := windowsTargetRuntimeRequestTrust
	originalAdmin := windowsTargetRuntimeAdminValidate
	t.Cleanup(func() {
		windowsTargetRuntimeRequestTrust = originalTrust
		windowsTargetRuntimeAdminValidate = originalAdmin
	})

	path := filepath.Join(t.TempDir(), "report.json")
	const original = "do-not-overwrite"
	if err := os.WriteFile(path, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}
	windowsTargetRuntimeRequestTrust = func(string, string) error { return nil }
	windowsTargetRuntimeAdminValidate = func(string) error { return errors.New("wrong protected output DACL") }
	if err := writeWindowsTargetRuntimeProtectedJSON(path, map[string]bool{"ok": true}); err == nil {
		t.Fatal("overwrote output rejected by AdminFile validation")
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != original {
		t.Fatalf("rejected output changed: data=%q err=%v", data, err)
	}
}

func TestWindowsTargetRuntimeManifestDigestIsPinnedDuringLoad(t *testing.T) {
	originalTrust := windowsTargetRuntimeManifestTrust
	originalAdmin := windowsTargetRuntimeAdminValidate
	originalLoad := windowsTargetRuntimeManifestLoad
	t.Cleanup(func() {
		windowsTargetRuntimeManifestTrust = originalTrust
		windowsTargetRuntimeAdminValidate = originalAdmin
		windowsTargetRuntimeManifestLoad = originalLoad
	})

	path := filepath.Join(t.TempDir(), "targets.yaml")
	raw := []byte("version: 1\ntargets: []\n")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	windowsTargetRuntimeManifestTrust = func(string, string) error { return nil }
	windowsTargetRuntimeAdminValidate = func(string) error { return nil }
	windowsTargetRuntimeManifestLoad = func(got string) (enterprisehooks.Manifest, error) {
		ptr, err := windows.UTF16PtrFromString(got)
		if err != nil {
			return enterprisehooks.Manifest{}, err
		}
		handle, openErr := windows.CreateFile(ptr, windows.GENERIC_WRITE, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
		if openErr == nil {
			_ = windows.CloseHandle(handle)
			return enterprisehooks.Manifest{}, errors.New("manifest writer opened while digest handle was pinned")
		}
		if !errors.Is(openErr, windows.ERROR_SHARING_VIOLATION) {
			return enterprisehooks.Manifest{}, fmt.Errorf("manifest pin returned %w, want sharing violation", openErr)
		}
		return enterprisehooks.Manifest{Version: 1}, nil
	}
	manifest, digest, err := loadWindowsTargetRuntimeManifest(path)
	if err != nil {
		t.Fatal(err)
	}
	want := fmt.Sprintf("%x", sha256.Sum256(raw))
	if manifest.Version != 1 || digest != want || digest != strings.ToLower(digest) {
		t.Fatalf("manifest=%+v digest=%q want=%q", manifest, digest, want)
	}
}

func TestWindowsTargetRuntimePublicErrorDoesNotLeakProtectedCause(t *testing.T) {
	const marker = "S-1-5-21-1-2-3-4-5-6-7-8"
	err := windowsTargetRuntimePublicMutationError("stage", fmt.Errorf("marker %s failed", marker))
	if strings.Contains(err.Error(), marker) || err.Error() != "target-runtime stage failed; inspect the protected report" {
		t.Fatalf("public error leaked protected cause: %q", err)
	}
}

func TestWindowsTargetRuntimeActionAndClaimsSchemas(t *testing.T) {
	command := newWindowsTargetRuntimeCommand()
	want := map[string]struct{}{"plan": {}, "stage": {}, "finalize": {}, "cleanup": {}}
	for _, child := range command.Commands() {
		if _, ok := want[child.Name()]; !ok {
			t.Fatalf("unexpected target-runtime action %q", child.Name())
		}
		delete(want, child.Name())
		if !child.Hidden || child.Flags().Lookup("output") == nil {
			t.Fatalf("action %q is not hidden or lacks protected output", child.Name())
		}
		if child.Name() == "plan" {
			if child.Flags().Lookup("manifest") == nil || child.Flags().Lookup("request") != nil {
				t.Fatalf("plan action flags are noncanonical")
			}
		} else if child.Flags().Lookup("request") == nil {
			t.Fatalf("action %q lacks protected request", child.Name())
		}
	}
	if len(want) != 0 {
		t.Fatalf("missing target-runtime actions: %v", want)
	}
	for _, action := range []string{"stage", "finalize"} {
		if err := validateWindowsTargetRuntimeClaimsReport(enterprisehooks.WindowsManagedRuntimeReport{SchemaVersion: enterprisehooks.WindowsManagedRuntimeReportSchemaVersion, Action: action}); err != nil {
			t.Fatalf("rejected claims action %q: %v", action, err)
		}
	}
	for _, report := range []enterprisehooks.WindowsManagedRuntimeReport{
		{SchemaVersion: enterprisehooks.WindowsManagedRuntimeReportSchemaVersion + 1, Action: "stage"},
		{SchemaVersion: enterprisehooks.WindowsManagedRuntimeReportSchemaVersion, Action: "cleanup"},
		{SchemaVersion: enterprisehooks.WindowsManagedRuntimeReportSchemaVersion, Action: "unknown"},
	} {
		if err := validateWindowsTargetRuntimeClaimsReport(report); err == nil {
			t.Fatalf("accepted unsupported claims report %+v", report)
		}
	}
}
