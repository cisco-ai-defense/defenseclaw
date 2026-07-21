// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows/registry"
)

const testInstalledAppKey = "DefenseClaw"

func TestInstalledAppSameLocationWithoutValidOwnerSurvivesMutationAttempts(t *testing.T) {
	transactionID := "0123456789abcdef0123456789abcdef"
	for _, test := range []struct {
		name        string
		ownerMarker string
	}{
		{name: "missing owner marker"},
		{name: "invalid owner marker", ownerMarker: "not-a-native-transaction"},
		{name: "valid but foreign owner marker", ownerMarker: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
	} {
		t.Run(test.name, func(t *testing.T) {
			registryPath := newInstalledAppTestRegistry(t)
			installRoot := `C:\Users\runneradmin\AppData\Local\Programs\DefenseClaw`
			key := createInstalledAppTestKey(t, registryPath)
			if err := key.SetStringValue("InstallLocation", installRoot); err != nil {
				t.Fatal(err)
			}
			if err := key.SetStringValue("DisplayName", "Foreign same-location registration"); err != nil {
				t.Fatal(err)
			}
			if test.ownerMarker != "" {
				if err := key.SetStringValue(installedAppOwnerValue, test.ownerMarker); err != nil {
					t.Fatal(err)
				}
			}
			if err := key.Close(); err != nil {
				t.Fatal(err)
			}

			if err := validateInstalledAppMutationAt(
				registryPath,
				testInstalledAppKey,
				installRoot,
				nil,
			); err == nil {
				t.Fatal("same-location foreign registration passed the pre-transaction ownership gate")
			}
			if err := registerInstalledAppAt(
				registryPath,
				testInstalledAppKey,
				filepath.Join(installRoot, "InstallerCache", setupArtifactName),
				installRoot,
				"1.2.3",
				transactionID,
				false,
				nil,
			); err == nil {
				t.Fatal("same-location foreign registration was overwritten during convergence")
			}
			if err := unregisterInstalledAppOwnedAt(
				registryPath,
				testInstalledAppKey,
				installRoot,
				nil,
			); err != nil {
				t.Fatal(err)
			}

			preserved, err := registry.OpenKey(
				registry.CURRENT_USER,
				registryPath+`\`+testInstalledAppKey,
				registry.QUERY_VALUE,
			)
			if err != nil {
				t.Fatalf("same-location foreign registration was deleted: %v", err)
			}
			defer preserved.Close()
			if displayName, _, err := preserved.GetStringValue("DisplayName"); err != nil ||
				displayName != "Foreign same-location registration" {
				t.Fatalf("foreign registration changed: DisplayName=%q err=%v", displayName, err)
			}
			if owner, _, err := preserved.GetStringValue(installedAppOwnerValue); test.ownerMarker == "" {
				if err != registry.ErrNotExist {
					t.Fatalf("missing foreign owner marker changed to %q: %v", owner, err)
				}
			} else if err != nil || owner != test.ownerMarker {
				t.Fatalf("foreign owner marker changed to %q: %v", owner, err)
			}
		})
	}
}

func TestInstalledAppLegacyStateProofAllowsOneTimeOwnerMigration(t *testing.T) {
	registryPath := newInstalledAppTestRegistry(t)
	installRoot := `C:\Users\runneradmin\AppData\Local\Programs\DefenseClaw`
	maintenancePath := `C:\Users\runneradmin\AppData\Local\DefenseClaw\InstallerCache\DefenseClawSetup-x64.exe`
	previous := &installState{
		Version:               "1.2.3",
		InstallRoot:           installRoot,
		MaintenancePath:       maintenancePath,
		UnsignedLocalArtifact: true,
	}
	writeLegacyInstalledAppTestKey(t, registryPath, previous)

	if err := validateInstalledAppMutationAt(
		registryPath,
		testInstalledAppKey,
		installRoot,
		previous,
	); err != nil {
		t.Fatalf("validated legacy native registration was not migratable: %v", err)
	}
	transactionID := "fedcba9876543210fedcba9876543210"
	if err := registerInstalledAppAt(
		registryPath,
		testInstalledAppKey,
		maintenancePath,
		installRoot,
		"1.2.4",
		transactionID,
		true,
		previous,
	); err != nil {
		t.Fatalf("migrate validated legacy registration: %v", err)
	}
	exists, owned, owner, err := installedAppRegistrationAt(
		registryPath,
		testInstalledAppKey,
		installRoot,
	)
	if err != nil || !exists || !owned || owner != transactionID {
		t.Fatalf("migrated ownership = exists:%t owned:%t owner:%q err:%v", exists, owned, owner, err)
	}
	installedState := *previous
	installedState.TransactionID = transactionID
	if err := unregisterInstalledAppOwnedAt(
		registryPath,
		testInstalledAppKey,
		installRoot,
		&installedState,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := registry.OpenKey(
		registry.CURRENT_USER,
		registryPath+`\`+testInstalledAppKey,
		registry.QUERY_VALUE,
	); err != registry.ErrNotExist {
		t.Fatalf("owned migrated registration survived uninstall: %v", err)
	}
}

func TestInstalledAppOwnerMarkerMustMatchDurablePreviousState(t *testing.T) {
	registryPath := newInstalledAppTestRegistry(t)
	installRoot := `C:\Users\runneradmin\AppData\Local\Programs\DefenseClaw`
	ownerTransaction := "11111111111111111111111111111111"
	foreignPrevious := &installState{TransactionID: "22222222222222222222222222222222"}
	key := createInstalledAppTestKey(t, registryPath)
	for name, value := range map[string]string{
		"InstallLocation":      installRoot,
		installedAppOwnerValue: ownerTransaction,
		"DisplayName":          "transaction-bound registration",
	} {
		if err := key.SetStringValue(name, value); err != nil {
			t.Fatal(err)
		}
	}
	if err := key.Close(); err != nil {
		t.Fatal(err)
	}

	if err := validateInstalledAppMutationAt(
		registryPath,
		testInstalledAppKey,
		installRoot,
		foreignPrevious,
	); err == nil {
		t.Fatal("valid marker owned by another transaction passed validation")
	}
	if err := unregisterInstalledAppOwnedAt(
		registryPath,
		testInstalledAppKey,
		installRoot,
		foreignPrevious,
	); err != nil {
		t.Fatal(err)
	}
	preserved, err := registry.OpenKey(
		registry.CURRENT_USER,
		registryPath+`\`+testInstalledAppKey,
		registry.QUERY_VALUE,
	)
	if err != nil {
		t.Fatalf("foreign transaction marker was deleted: %v", err)
	}
	if err := preserved.Close(); err != nil {
		t.Fatal(err)
	}

	ownedPrevious := &installState{TransactionID: ownerTransaction}
	if err := validateInstalledAppMutationAt(
		registryPath,
		testInstalledAppKey,
		installRoot,
		ownedPrevious,
	); err != nil {
		t.Fatalf("matching durable transaction owner was rejected: %v", err)
	}
	if err := unregisterInstalledAppOwnedAt(
		registryPath,
		testInstalledAppKey,
		installRoot,
		ownedPrevious,
	); err != nil {
		t.Fatal(err)
	}
	if key, err := registry.OpenKey(
		registry.CURRENT_USER,
		registryPath+`\`+testInstalledAppKey,
		registry.QUERY_VALUE,
	); err != registry.ErrNotExist {
		if err == nil {
			_ = key.Close()
		}
		t.Fatalf("matching transaction-owned registration survived uninstall: %v", err)
	}
}

func TestInstalledAppExistingUpdateDoesNotClaimRenamedKey(t *testing.T) {
	registryPath := newInstalledAppTestRegistry(t)
	installRoot := `C:\Users\runneradmin\AppData\Local\Programs\DefenseClaw`
	maintenancePath := `C:\Users\runneradmin\AppData\Local\DefenseClaw\InstallerCache\DefenseClawSetup-x64.exe`
	previousTransaction := "33333333333333333333333333333333"
	currentTransaction := "44444444444444444444444444444444"
	previous := &installState{TransactionID: previousTransaction}
	writeInstalledAppTestValues(
		t,
		registryPath,
		testInstalledAppKey,
		maintenancePath,
		installRoot,
		"1.2.3",
		previousTransaction,
		false,
	)

	err := registerInstalledAppAtWithHook(
		registryPath,
		testInstalledAppKey,
		maintenancePath,
		installRoot,
		"1.2.4",
		currentTransaction,
		false,
		previous,
		func() {
			renameInstalledAppTestKey(t, registryPath, testInstalledAppKey, testInstalledAppKey+".renamed")
			writeForeignInstalledAppTestKey(t, registryPath, testInstalledAppKey, "Foreign concurrent registration")
		},
	)
	if err == nil || !strings.Contains(err.Error(), "changed during handle-bound update") {
		t.Fatalf("renamed handle update did not fail closed: %v", err)
	}
	assertInstalledAppTestDisplayName(t, registryPath, testInstalledAppKey, "Foreign concurrent registration")

	matches, matchErr := installedAppValuesMatchAt(
		registryPath,
		testInstalledAppKey+".renamed",
		maintenancePath,
		installRoot,
		"1.2.4",
		currentTransaction,
		false,
	)
	if matchErr != nil || !matches {
		t.Fatalf("handle-bound update did not stay on the validated key: matches=%t err=%v", matches, matchErr)
	}
}

func TestInstalledAppUninstallDeletesValidatedKeyHandleOnly(t *testing.T) {
	registryPath := newInstalledAppTestRegistry(t)
	installRoot := `C:\Users\runneradmin\AppData\Local\Programs\DefenseClaw`
	maintenancePath := `C:\Users\runneradmin\AppData\Local\DefenseClaw\InstallerCache\DefenseClawSetup-x64.exe`
	transactionID := "55555555555555555555555555555555"
	previous := &installState{TransactionID: transactionID}
	writeInstalledAppTestValues(
		t,
		registryPath,
		testInstalledAppKey,
		maintenancePath,
		installRoot,
		"1.2.3",
		transactionID,
		false,
	)

	err := unregisterInstalledAppOwnedAtWithHook(
		registryPath,
		testInstalledAppKey,
		installRoot,
		previous,
		func() {
			renameInstalledAppTestKey(t, registryPath, testInstalledAppKey, testInstalledAppKey+".renamed")
			writeForeignInstalledAppTestKey(t, registryPath, testInstalledAppKey, "Foreign replacement registration")
		},
	)
	if err != nil {
		t.Fatalf("delete validated registry key handle: %v", err)
	}
	assertInstalledAppTestDisplayName(t, registryPath, testInstalledAppKey, "Foreign replacement registration")
	if key, openErr := registry.OpenKey(
		registry.CURRENT_USER,
		registryPath+`\`+testInstalledAppKey+".renamed",
		registry.QUERY_VALUE,
	); openErr != registry.ErrNotExist {
		if openErr == nil {
			_ = key.Close()
		}
		t.Fatalf("validated renamed registry object survived exact-handle deletion: %v", openErr)
	}
}

func TestInstalledAppFreshPublicationRejectsPartialSameTransactionDestination(t *testing.T) {
	registryPath := newInstalledAppTestRegistry(t)
	installRoot := `C:\Users\runneradmin\AppData\Local\Programs\DefenseClaw`
	maintenancePath := `C:\Users\runneradmin\AppData\Local\DefenseClaw\InstallerCache\DefenseClawSetup-x64.exe`
	transactionID := "66666666666666666666666666666666"
	stagingName := testInstalledAppKey + ".pending." + transactionID

	err := registerInstalledAppAtWithHooks(
		registryPath,
		testInstalledAppKey,
		maintenancePath,
		installRoot,
		"1.2.3",
		transactionID,
		false,
		nil,
		nil,
		nil,
		func() {
			key := createInstalledAppTestKeyNamed(t, registryPath, testInstalledAppKey)
			defer key.Close()
			for name, value := range map[string]string{
				installedAppOwnerValue: transactionID,
				"InstallLocation":      installRoot,
				"DisplayName":          "Partial concurrent registration",
			} {
				if setErr := key.SetStringValue(name, value); setErr != nil {
					t.Fatalf("write partial concurrent %s: %v", name, setErr)
				}
			}
		},
	)
	if err == nil {
		t.Fatal("partial same-transaction destination was accepted as a completed publication")
	}
	assertInstalledAppTestDisplayName(t, registryPath, testInstalledAppKey, "Partial concurrent registration")
	if key, openErr := registry.OpenKey(
		registry.CURRENT_USER,
		registryPath+`\`+stagingName,
		registry.QUERY_VALUE,
	); openErr != nil {
		t.Fatalf("transaction-owned staging evidence was not retained: %v", openErr)
	} else if closeErr := key.Close(); closeErr != nil {
		t.Fatal(closeErr)
	}
}

func TestInstalledAppCommittedUpdateUsesOneRegistrationSnapshot(t *testing.T) {
	registryPath := newInstalledAppTestRegistry(t)
	installRoot := filepath.Join(t.TempDir(), "Programs", "DefenseClaw")
	maintenancePath := filepath.Join(t.TempDir(), "InstallerCache", setupArtifactName)
	previousTransaction := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	currentTransaction := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	previous := &installState{TransactionID: previousTransaction}
	if err := os.MkdirAll(filepath.Join(installRoot, "bin"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(installRoot, "bin", "defenseclaw.exe"), make([]byte, 1024), 0o600); err != nil {
		t.Fatal(err)
	}
	writeInstalledAppTestValues(
		t,
		registryPath,
		testInstalledAppKey,
		maintenancePath,
		installRoot,
		"0.8.0",
		previousTransaction,
		false,
	)

	writtenEstimatedSize := estimateInstallKB(installRoot)
	phase := setupPhaseCommitted
	err := recoverSetupJournalPhase(setupJournal{
		SchemaVersion: setupJournalSchemaVersion,
		Phase:         setupPhaseCommitted,
		Transaction:   setupTransaction{Action: "install"},
	}, setupRecoveryOps{
		Converge: func(setupTransaction) error {
			return registerInstalledAppAtWithHooks(
				registryPath,
				testInstalledAppKey,
				maintenancePath,
				installRoot,
				"0.8.6",
				currentTransaction,
				false,
				previous,
				nil,
				func() {
					if writeErr := os.WriteFile(
						filepath.Join(installRoot, "bin", "setup-owned-cache.bin"),
						make([]byte, 4096),
						0o600,
					); writeErr != nil {
						t.Fatal(writeErr)
					}
				},
				nil,
			)
		},
		Cleanup: func(setupTransaction) error { return nil },
		Transition: func(_ setupTransaction, from, to string) error {
			if phase != from {
				return fmt.Errorf("journal transition from %s while phase is %s", from, phase)
			}
			phase = to
			return nil
		},
	})
	if err != nil {
		t.Fatalf("committed registration convergence: %v", err)
	}
	if phase != setupPhaseComplete {
		t.Fatalf("journal phase = %q, want %q", phase, setupPhaseComplete)
	}
	key, err := registry.OpenKey(
		registry.CURRENT_USER,
		registryPath+`\`+testInstalledAppKey,
		registry.QUERY_VALUE,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer key.Close()
	owner, _, err := key.GetStringValue(installedAppOwnerValue)
	if err != nil || owner != currentTransaction {
		t.Fatalf("registration owner = %q, %v", owner, err)
	}
	displayVersion, _, err := key.GetStringValue("DisplayVersion")
	if err != nil || displayVersion != "0.8.6" {
		t.Fatalf("registration version = %q, %v", displayVersion, err)
	}
	estimatedSize, _, err := key.GetIntegerValue("EstimatedSize")
	if err != nil || estimatedSize != uint64(writtenEstimatedSize) {
		t.Fatalf("registration size = %d, %v; want snapshot %d", estimatedSize, err, writtenEstimatedSize)
	}
}

func TestUninstallHandoffRetiresOnlySourceTransactionPendingInstalledAppKey(t *testing.T) {
	registryPath := newInstalledAppTestRegistry(t)
	installRoot := `C:\Users\runneradmin\AppData\Local\Programs\DefenseClaw`
	sourceTransaction := "77777777777777777777777777777777"
	otherTransaction := "88888888888888888888888888888888"
	sourceName := testInstalledAppKey + ".pending." + sourceTransaction
	otherName := testInstalledAppKey + ".pending." + otherTransaction

	for name, transactionID := range map[string]string{
		sourceName: sourceTransaction,
		otherName:  otherTransaction,
	} {
		key := createInstalledAppTestKeyNamed(t, registryPath, name)
		if err := key.SetStringValue(installedAppOwnerValue, transactionID); err != nil {
			_ = key.Close()
			t.Fatal(err)
		}
		if err := key.SetStringValue("InstallLocation", installRoot); err != nil {
			_ = key.Close()
			t.Fatal(err)
		}
		if err := key.Close(); err != nil {
			t.Fatal(err)
		}
	}

	if err := retireInstalledAppPendingOwnedAt(
		registryPath,
		testInstalledAppKey,
		installRoot,
		sourceTransaction,
	); err != nil {
		t.Fatalf("retire source transaction staging: %v", err)
	}
	if key, err := registry.OpenKey(
		registry.CURRENT_USER,
		registryPath+`\`+sourceName,
		registry.QUERY_VALUE,
	); err != registry.ErrNotExist {
		if err == nil {
			_ = key.Close()
		}
		t.Fatalf("source transaction staging survived handoff: %v", err)
	}
	other, err := registry.OpenKey(
		registry.CURRENT_USER,
		registryPath+`\`+otherName,
		registry.QUERY_VALUE,
	)
	if err != nil {
		t.Fatalf("another transaction staging was removed: %v", err)
	}
	if err := other.Close(); err != nil {
		t.Fatal(err)
	}

	// A crash after exact-handle deletion but before journal handoff must be
	// recoverable: the retained source journal authorizes an idempotent retry.
	if err := retireInstalledAppPendingOwnedAt(
		registryPath,
		testInstalledAppKey,
		installRoot,
		sourceTransaction,
	); err != nil {
		t.Fatalf("retry retirement after crash boundary: %v", err)
	}
}

func TestUninstallHandoffRetiresEmptySourceTransactionPendingInstalledAppKey(t *testing.T) {
	registryPath := newInstalledAppTestRegistry(t)
	installRoot := `C:\Users\runneradmin\AppData\Local\Programs\DefenseClaw`
	transactionID := "99999999999999999999999999999999"
	stagingName := testInstalledAppKey + ".pending." + transactionID
	key := createInstalledAppTestKeyNamed(t, registryPath, stagingName)
	if err := key.Close(); err != nil {
		t.Fatal(err)
	}

	if err := retireInstalledAppPendingOwnedAt(
		registryPath,
		testInstalledAppKey,
		installRoot,
		transactionID,
	); err != nil {
		t.Fatalf("retire create-before-first-value staging key: %v", err)
	}
	if key, err := registry.OpenKey(
		registry.CURRENT_USER,
		registryPath+`\`+stagingName,
		registry.QUERY_VALUE,
	); err != registry.ErrNotExist {
		if err == nil {
			_ = key.Close()
		}
		t.Fatalf("empty transaction staging survived handoff: %v", err)
	}
}

func TestUninstallHandoffRejectsMismatchedSourceNamedPendingInstalledAppKey(t *testing.T) {
	installRoot := `C:\Users\runneradmin\AppData\Local\Programs\DefenseClaw`
	transactionID := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	for _, test := range []struct {
		name     string
		owner    string
		location string
	}{
		{
			name:     "foreign owner",
			owner:    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			location: installRoot,
		},
		{
			name:     "foreign install location",
			owner:    transactionID,
			location: `C:\Foreign\DefenseClaw`,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			registryPath := newInstalledAppTestRegistry(t)
			stagingName := testInstalledAppKey + ".pending." + transactionID
			key := createInstalledAppTestKeyNamed(t, registryPath, stagingName)
			if err := key.SetStringValue(installedAppOwnerValue, test.owner); err != nil {
				_ = key.Close()
				t.Fatal(err)
			}
			if err := key.SetStringValue("InstallLocation", test.location); err != nil {
				_ = key.Close()
				t.Fatal(err)
			}
			if err := key.Close(); err != nil {
				t.Fatal(err)
			}

			if err := retireInstalledAppPendingOwnedAt(
				registryPath,
				testInstalledAppKey,
				installRoot,
				transactionID,
			); err == nil {
				t.Fatal("mismatched source-named staging key was deleted")
			}
			preserved, err := registry.OpenKey(
				registry.CURRENT_USER,
				registryPath+`\`+stagingName,
				registry.QUERY_VALUE,
			)
			if err != nil {
				t.Fatalf("mismatched staging key was not preserved: %v", err)
			}
			if err := preserved.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestUninstallHandoffDoesNotClaimConcurrentPendingKeyReplacement(t *testing.T) {
	registryPath := newInstalledAppTestRegistry(t)
	installRoot := `C:\Users\runneradmin\AppData\Local\Programs\DefenseClaw`
	transactionID := "cccccccccccccccccccccccccccccccc"
	stagingName := testInstalledAppKey + ".pending." + transactionID
	renamedName := stagingName + ".renamed"
	key := createInstalledAppTestKeyNamed(t, registryPath, stagingName)
	if err := key.SetStringValue(installedAppOwnerValue, transactionID); err != nil {
		_ = key.Close()
		t.Fatal(err)
	}
	if err := key.SetStringValue("InstallLocation", installRoot); err != nil {
		_ = key.Close()
		t.Fatal(err)
	}
	if err := key.Close(); err != nil {
		t.Fatal(err)
	}

	err := retireInstalledAppPendingOwnedAtWithHook(
		registryPath,
		testInstalledAppKey,
		installRoot,
		transactionID,
		func() {
			renameInstalledAppTestKey(t, registryPath, stagingName, renamedName)
			writeForeignInstalledAppTestKey(t, registryPath, stagingName, "Concurrent pending replacement")
		},
	)
	if err == nil || !strings.Contains(err.Error(), "changed during exact-handle retirement") {
		t.Fatalf("concurrent pending replacement was reported as retired: %v", err)
	}
	assertInstalledAppTestDisplayName(t, registryPath, stagingName, "Concurrent pending replacement")
	if key, openErr := registry.OpenKey(
		registry.CURRENT_USER,
		registryPath+`\`+renamedName,
		registry.QUERY_VALUE,
	); openErr != registry.ErrNotExist {
		if openErr == nil {
			_ = key.Close()
		}
		t.Fatalf("validated source pending key survived exact-handle deletion: %v", openErr)
	}
}

func newInstalledAppTestRegistry(t *testing.T) string {
	t.Helper()
	registryPath := fmt.Sprintf(
		`Software\DefenseClawSetupTests\installed-app-%d-%d`,
		os.Getpid(),
		time.Now().UnixNano(),
	)
	key, _, err := registry.CreateKey(registry.CURRENT_USER, registryPath, registry.ALL_ACCESS)
	if err != nil {
		t.Fatal(err)
	}
	if err := key.Close(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		parent, err := registry.OpenKey(registry.CURRENT_USER, registryPath, registry.ENUMERATE_SUB_KEYS)
		if err == nil {
			names, readErr := parent.ReadSubKeyNames(-1)
			_ = parent.Close()
			if readErr == nil {
				for _, name := range names {
					_ = registry.DeleteKey(registry.CURRENT_USER, registryPath+`\`+name)
				}
			}
		}
		_ = registry.DeleteKey(registry.CURRENT_USER, registryPath)
	})
	return registryPath
}

func createInstalledAppTestKey(t *testing.T, registryPath string) registry.Key {
	t.Helper()
	return createInstalledAppTestKeyNamed(t, registryPath, testInstalledAppKey)
}

func createInstalledAppTestKeyNamed(t *testing.T, registryPath, registryKey string) registry.Key {
	t.Helper()
	key, _, err := registry.CreateKey(
		registry.CURRENT_USER,
		registryPath+`\`+registryKey,
		registry.ALL_ACCESS,
	)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func writeInstalledAppTestValues(
	t *testing.T,
	registryPath, registryKey, maintenancePath, installRoot, version, transactionID string,
	unsigned bool,
) {
	t.Helper()
	key := createInstalledAppTestKeyNamed(t, registryPath, registryKey)
	if err := writeInstalledAppValues(
		key,
		maintenancePath,
		installRoot,
		version,
		transactionID,
		unsigned,
	); err != nil {
		_ = key.Close()
		t.Fatal(err)
	}
	if err := key.Close(); err != nil {
		t.Fatal(err)
	}
}

func renameInstalledAppTestKey(t *testing.T, registryPath, oldName, newName string) {
	t.Helper()
	parent, err := registry.OpenKey(registry.CURRENT_USER, registryPath, registry.ALL_ACCESS)
	if err != nil {
		t.Fatal(err)
	}
	if err := renameRegistrySubkey(parent, oldName, newName); err != nil {
		_ = parent.Close()
		t.Fatal(err)
	}
	if err := parent.Close(); err != nil {
		t.Fatal(err)
	}
}

func writeForeignInstalledAppTestKey(t *testing.T, registryPath, registryKey, displayName string) {
	t.Helper()
	key := createInstalledAppTestKeyNamed(t, registryPath, registryKey)
	if err := key.SetStringValue("DisplayName", displayName); err != nil {
		_ = key.Close()
		t.Fatal(err)
	}
	if err := key.Close(); err != nil {
		t.Fatal(err)
	}
}

func assertInstalledAppTestDisplayName(t *testing.T, registryPath, registryKey, want string) {
	t.Helper()
	key, err := registry.OpenKey(
		registry.CURRENT_USER,
		registryPath+`\`+registryKey,
		registry.QUERY_VALUE,
	)
	if err != nil {
		t.Fatalf("open %s: %v", registryKey, err)
	}
	got, _, valueErr := key.GetStringValue("DisplayName")
	closeErr := key.Close()
	if valueErr != nil || closeErr != nil || got != want {
		t.Fatalf("%s DisplayName=%q, want %q (read=%v close=%v)", registryKey, got, want, valueErr, closeErr)
	}
}

func writeLegacyInstalledAppTestKey(t *testing.T, registryPath string, state *installState) {
	t.Helper()
	key := createInstalledAppTestKey(t, registryPath)
	defer key.Close()
	displayName := productName
	if state.UnsignedLocalArtifact {
		displayName += " (Unsigned Local Test Build)"
	}
	values := map[string]string{
		"DisplayName":          displayName,
		"DisplayVersion":       state.Version,
		"Publisher":            defaultPublisher,
		"InstallLocation":      state.InstallRoot,
		"DisplayIcon":          filepath.Join(state.InstallRoot, "bin", "defenseclaw.exe"),
		"UninstallString":      quote(state.MaintenancePath) + " /uninstall",
		"QuietUninstallString": quote(state.MaintenancePath) + " /uninstall /quiet",
		"ModifyPath":           quote(state.MaintenancePath) + " /repair",
		"URLInfoAbout":         "https://github.com/cisco-ai-defense/defenseclaw",
	}
	for name, value := range values {
		if err := key.SetStringValue(name, value); err != nil {
			t.Fatalf("write legacy %s: %v", name, err)
		}
	}
}

func TestLegacyInstalledAppProofRejectsPartialLookalike(t *testing.T) {
	registryPath := newInstalledAppTestRegistry(t)
	installRoot := `C:\Users\runneradmin\AppData\Local\Programs\DefenseClaw`
	state := &installState{
		Version:         "1.2.3",
		InstallRoot:     installRoot,
		MaintenancePath: `C:\Users\runneradmin\AppData\Local\DefenseClaw\InstallerCache\DefenseClawSetup-x64.exe`,
	}
	writeLegacyInstalledAppTestKey(t, registryPath, state)
	key, err := registry.OpenKey(
		registry.CURRENT_USER,
		registryPath+`\`+testInstalledAppKey,
		registry.SET_VALUE,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := key.SetStringValue("Publisher", "Foreign Publisher"); err != nil {
		t.Fatal(err)
	}
	if err := key.Close(); err != nil {
		t.Fatal(err)
	}
	if err := validateInstalledAppMutationAt(
		registryPath,
		testInstalledAppKey,
		installRoot,
		state,
	); err == nil || !strings.Contains(err.Error(), "unrelated Apps & Features registration") {
		t.Fatalf("partial legacy lookalike passed ownership validation: %v", err)
	}
}
