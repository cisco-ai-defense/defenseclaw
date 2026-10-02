// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// writeHealthyGuardianRecords publishes a fresh, matching guardian state,
// authorization and activation for rows and points the status command at
// them.
func writeHealthyGuardianRecords(t *testing.T, rows []enterpriseHookReconcileRow) {
	t.Helper()
	originalCfg, originalManifest, originalJSON := cfg, enterpriseHookManifest, enterpriseHookJSON
	originalStateTrust := enterpriseHookGuardianStateFileTrustCheck
	originalAuthorizationTrust := enterpriseHookAuthorizationFileTrustCheck
	originalManifestTrust := enterpriseHookManifestFileTrustCheck
	t.Cleanup(func() {
		cfg, enterpriseHookManifest, enterpriseHookJSON = originalCfg, originalManifest, originalJSON
		enterpriseHookGuardianStateFileTrustCheck = originalStateTrust
		enterpriseHookAuthorizationFileTrustCheck = originalAuthorizationTrust
		enterpriseHookManifestFileTrustCheck = originalManifestTrust
	})
	scope := t.TempDir()
	dataDir := filepath.Join(scope, "runtime")
	authorizationDir := filepath.Join(scope, "authorization")
	manifest := filepath.Join(scope, "hook-guardian", "targets.yaml")
	for _, dir := range []string{dataDir, authorizationDir, filepath.Dir(manifest)} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv(hookGuardianAuthorizationDirEnv, authorizationDir)
	enterpriseHookGuardianStateFileTrustCheck = func(string) error { return nil }
	enterpriseHookAuthorizationFileTrustCheck = func(string) error { return nil }
	enterpriseHookManifestFileTrustCheck = func(string) error { return nil }
	if err := os.WriteFile(manifest, []byte("version: 1\ntargets: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, manifestSHA256, err := enterprisehooks.LoadManifestWithSHA256(manifest)
	if err != nil {
		t.Fatal(err)
	}
	updatedAt := time.Now().UTC().Format(time.RFC3339)
	success, pending := 0, 0
	for _, row := range rows {
		if row.OK {
			success++
		} else if row.Pending {
			pending++
		}
	}
	records := map[string]any{
		filepath.Join(dataDir, hookGuardianStateFile): enterpriseHookGuardianState{
			Version: 1, UpdatedAt: updatedAt, Manifest: manifest, OK: true,
			TargetCount: len(rows), SuccessCount: success, PendingCount: pending, Results: rows,
		},
		filepath.Join(authorizationDir, hookGuardianAuthorizationFile): enterpriseHookGuardianAuthorization{
			Version: 1, UpdatedAt: updatedAt, OK: true,
			TargetCount: len(rows), SuccessCount: success, PendingCount: pending, ProtectedTargets: rows,
		},
		filepath.Join(authorizationDir, hookGuardianActivationFile): enterpriseHookGuardianActivation{
			Version: enterpriseHookGuardianActivationVersion, UpdatedAt: updatedAt,
			ReconcileID: strings.Repeat("c", 32), Manifest: manifest, ManifestSHA256: manifestSHA256, OK: true,
			TargetCount: len(rows), SuccessCount: success, PendingCount: pending, ProtectedTargets: rows,
		},
	}
	for path, value := range records {
		body, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, append(body, '\n'), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	cfg = &config.Config{DataDir: dataDir, DeploymentMode: managed.DeploymentModeManagedEnterprise}
	enterpriseHookManifest = manifest
}

// `enterprise hooks status` lists who is enrolled for which connector, in
// text and JSON, instead of only counts.
func TestEnterpriseHooksStatusListsEnrollmentPerUserAndConnector(t *testing.T) {
	rows := []enterpriseHookReconcileRow{
		{User: "bob", UserHome: "/home/bob", UID: 1002, Connector: "codex", OK: true},
		{User: "alice", UserHome: "/home/alice", UID: 1001, Connector: "codex", OK: true},
		{User: "alice", UserHome: "/home/alice", UID: 1001, Connector: "claudecode", OK: true},
	}
	writeHealthyGuardianRecords(t, rows)

	enterpriseHookJSON = false
	var stdout, stderr bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	if err := runEnterpriseHooksStatus(cmd, nil); err != nil {
		t.Fatalf("status: %v; stderr=%s", err, stderr.String())
	}
	text := stdout.String()
	for _, want := range []string{
		"Enrollment (last guardian reconcile ",
		"    alice (/home/alice, uid 1001): claudecode enrolled, codex enrolled\n",
		"    bob (/home/bob, uid 1002): codex enrolled\n",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("text status does not contain %q:\n%s", want, text)
		}
	}

	enterpriseHookJSON = true
	stdout.Reset()
	if err := runEnterpriseHooksStatus(cmd, nil); err != nil {
		t.Fatalf("status --json: %v", err)
	}
	var report struct {
		Enrollment []struct {
			User       string `json:"user"`
			UID        int    `json:"uid"`
			Connectors []struct {
				Connector string `json:"connector"`
				State     string `json:"state"`
			} `json:"connectors"`
		} `json:"enrollment"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatalf("decode: %v\n%s", err, stdout.String())
	}
	if len(report.Enrollment) != 2 || report.Enrollment[0].User != "alice" || report.Enrollment[0].UID != 1001 ||
		len(report.Enrollment[0].Connectors) != 2 || report.Enrollment[0].Connectors[0].Connector != "claudecode" ||
		report.Enrollment[0].Connectors[0].State != "enrolled" || report.Enrollment[1].User != "bob" {
		t.Fatalf("JSON enrollment = %+v, want alice {claudecode, codex} and bob {codex}", report.Enrollment)
	}
}

func TestEnterpriseHookEnrollmentStates(t *testing.T) {
	got := enterpriseHookEnrollmentFromRows([]enterpriseHookReconcileRow{
		{SID: "S-1-5-21-1-2-3-1001", UserHome: `C:\Users\alice`, Connector: "cursor", Pending: true},
		{SID: "S-1-5-21-1-2-3-1001", UserHome: `C:\Users\alice`, Connector: "codex", Error: "hook contract drift"},
	})
	if len(got) != 1 || len(got[0].Connectors) != 2 ||
		got[0].Connectors[0] != (enterpriseHookEnrollmentState{Connector: "codex", State: "failed"}) ||
		got[0].Connectors[1] != (enterpriseHookEnrollmentState{Connector: "cursor", State: "pending"}) {
		t.Fatalf("enrollment = %+v", got)
	}
	var out bytes.Buffer
	printEnterpriseHookEnrollment(&out, got, "")
	want := "  Enrollment:\n    C:\\Users\\alice (S-1-5-21-1-2-3-1001): codex failed, cursor pending\n"
	if out.String() != want {
		t.Fatalf("text = %q, want %q", out.String(), want)
	}
}

// GAP-1867: an account whose home was deleted is shown as deleted, not with
// its agents pending, until the enumerator drops its rows.
func TestEnterpriseHookEnrollmentMarksADeletedAccount(t *testing.T) {
	kept := t.TempDir()
	gone := filepath.Join(t.TempDir(), "gone")
	got := enterpriseHookEnrollmentFromRows([]enterpriseHookReconcileRow{
		{User: "gone", UID: 506, UserHome: gone, Connector: "kiro", Pending: true},
		{User: "gone", UID: 506, UserHome: gone, Connector: "amp", Pending: true},
		{User: "kept", UID: 507, UserHome: kept, Connector: "amp", OK: true},
		// The last reconcile verified a hook there: not reported as deleted.
		{User: "verified", UID: 508, UserHome: filepath.Join(gone, "verified"), Connector: "codex", OK: true},
	})
	markEnterpriseHookDeletedAccounts(got)
	if len(got) != 3 || !got[0].AccountDeleted || got[1].AccountDeleted || got[2].AccountDeleted {
		t.Fatalf("enrollment = %+v, want only gone deleted", got)
	}
	got = got[:2]
	var out bytes.Buffer
	printEnterpriseHookEnrollment(&out, got, "")
	want := "  Enrollment:\n" +
		"    gone (" + gone + ", uid 506): account deleted, home removed (amp, kiro dropped at the hook enumerator's next pass)\n" +
		"    kept (" + kept + ", uid 507): amp enrolled\n"
	if out.String() != want {
		t.Fatalf("text = %q, want %q", out.String(), want)
	}
}
