// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

func stubEnterpriseHookGuardianLedger(
	t *testing.T,
	drifted map[string]bool,
	repairErr error,
) (*[]string, *[]string) {
	t.Helper()
	originalDir := enterpriseHookAuthorizationDirTrustCheck
	originalFile := enterpriseHookAuthorizationFileTrustCheck
	originalState := enterpriseHookGuardianStateFileTrustCheck
	originalRepairer := enterpriseHookGuardianLedgerRepairer
	originalSink := managed.ReportResilienceEvent
	t.Cleanup(func() {
		enterpriseHookAuthorizationDirTrustCheck = originalDir
		enterpriseHookAuthorizationFileTrustCheck = originalFile
		enterpriseHookGuardianStateFileTrustCheck = originalState
		enterpriseHookGuardianLedgerRepairer = originalRepairer
		managed.ReportResilienceEvent = originalSink
	})
	check := func(path string) error {
		if drifted[path] {
			return errors.New("untrusted write ACE")
		}
		return nil
	}
	enterpriseHookAuthorizationDirTrustCheck = check
	enterpriseHookAuthorizationFileTrustCheck = check
	enterpriseHookGuardianStateFileTrustCheck = check
	var repaired []string
	enterpriseHookGuardianLedgerRepairer = func(path string, _ bool) error {
		if repairErr != nil {
			return repairErr
		}
		repaired = append(repaired, path)
		delete(drifted, path)
		return nil
	}
	var events []string
	managed.ReportResilienceEvent = func(marker string, fields map[string]string) {
		events = append(events, managed.FormatResilienceEvent(marker, fields))
	}
	return &repaired, &events
}

func writeEnterpriseHookGuardianLedgerFixture(t *testing.T) (string, string) {
	t.Helper()
	dataDir := t.TempDir()
	t.Setenv(managed.HookGuardianAuthorizationDirEnv, "")
	authorizationDir := managed.HookGuardianAuthorizationDir(dataDir)
	if err := os.MkdirAll(authorizationDir, 0o750); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{
		filepath.Join(authorizationDir, hookGuardianAuthorizationFile),
		filepath.Join(dataDir, hookGuardianStateFile),
	} {
		if err := os.WriteFile(path, []byte("{}\n"), 0o640); err != nil {
			t.Fatal(err)
		}
	}
	return dataDir, authorizationDir
}

func TestRepairEnterpriseHookGuardianLedgerRestampsOnlyDriftedObjects(t *testing.T) {
	dataDir, authorizationDir := writeEnterpriseHookGuardianLedgerFixture(t)
	authorizationPath := filepath.Join(authorizationDir, hookGuardianAuthorizationFile)
	statePath := filepath.Join(dataDir, hookGuardianStateFile)
	drifted := map[string]bool{authorizationDir: true, statePath: true}
	repaired, events := stubEnterpriseHookGuardianLedger(t, drifted, nil)

	if err := repairEnterpriseHookGuardianLedger(dataDir); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(*repaired, []string{authorizationDir, statePath}) {
		t.Fatalf("repaired = %v", *repaired)
	}
	if slices.Contains(*repaired, authorizationPath) {
		t.Fatal("healthy authorization file was rewritten")
	}
	if len(*events) != 2 || !strings.HasPrefix((*events)[0], managed.MarkerRepair+" ") {
		t.Fatalf("events = %v", *events)
	}
}

func TestRepairEnterpriseHookGuardianLedgerSkipsMissingAndLinkedObjects(t *testing.T) {
	dataDir, authorizationDir := writeEnterpriseHookGuardianLedgerFixture(t)
	activationPath := filepath.Join(authorizationDir, hookGuardianActivationFile)
	statePath := filepath.Join(dataDir, hookGuardianStateFile)
	if err := os.Remove(statePath); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dataDir, "elsewhere"), statePath); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	drifted := map[string]bool{activationPath: true, statePath: true}
	repaired, _ := stubEnterpriseHookGuardianLedger(t, drifted, nil)

	if err := repairEnterpriseHookGuardianLedger(dataDir); err != nil {
		t.Fatal(err)
	}
	if len(*repaired) != 0 {
		t.Fatalf("repaired = %v; missing and linked objects must be left to validation", *repaired)
	}
}

func TestRepairEnterpriseHookGuardianLedgerReportsUnrepairableDrift(t *testing.T) {
	dataDir, authorizationDir := writeEnterpriseHookGuardianLedgerFixture(t)
	authorizationPath := filepath.Join(authorizationDir, hookGuardianAuthorizationFile)
	drifted := map[string]bool{authorizationPath: true}
	refused := errors.New("hook guardian ledger owner is not trusted")
	_, events := stubEnterpriseHookGuardianLedger(t, drifted, refused)

	err := repairEnterpriseHookGuardianLedger(dataDir)
	if !errors.Is(err, refused) || !strings.Contains(err.Error(), authorizationPath) {
		t.Fatalf("err = %v", err)
	}
	if len(*events) != 0 {
		t.Fatalf("events = %v", *events)
	}
}

func TestEnterpriseHookNoLifecycleTransactionPending(t *testing.T) {
	stateRoot := t.TempDir()
	dataDir := filepath.Join(stateRoot, "runtime")
	installDir := filepath.Join(stateRoot, "install")
	if err := os.MkdirAll(installDir, 0o750); err != nil {
		t.Fatal(err)
	}
	if !enterpriseHookNoLifecycleTransactionPending(dataDir) {
		t.Fatal("clean install folder reported a pending transaction")
	}
	for _, leaf := range []string{"pending.json", "managed-hooks-lifecycle-journal.json"} {
		path := filepath.Join(installDir, leaf)
		if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
		if enterpriseHookNoLifecycleTransactionPending(dataDir) {
			t.Fatalf("%s present but no pending transaction reported", leaf)
		}
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
	}
	if enterpriseHookNoLifecycleTransactionPending("") {
		t.Fatal("empty data dir must count as pending")
	}
}
