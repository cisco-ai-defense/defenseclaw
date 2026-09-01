// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

// published087SetupTransaction is the exact strict transaction JSON surface
// shipped by the 0.8.7 Setup source at 57393d05, before 0.8.8 added stable-hook
// posture fields without changing the outer journal schema version.
type published087SetupTransaction struct {
	SchemaVersion                  int                      `json:"schema_version"`
	ID                             string                   `json:"id"`
	Action                         string                   `json:"action"`
	InstallRoot                    string                   `json:"install_root"`
	DataRoot                       string                   `json:"data_root"`
	MaintenancePath                string                   `json:"maintenance_path"`
	StagingPath                    string                   `json:"staging_path"`
	BackupPath                     string                   `json:"backup_path"`
	TrashPath                      string                   `json:"trash_path"`
	MaintenanceNew                 string                   `json:"maintenance_new"`
	MaintenanceBackup              string                   `json:"maintenance_backup"`
	HadInstall                     bool                     `json:"had_install"`
	MaintenanceExisted             bool                     `json:"maintenance_existed"`
	PreviousMaintenanceSHA256      string                   `json:"previous_maintenance_sha256,omitempty"`
	PreviousState                  *installState            `json:"previous_state,omitempty"`
	PreviousPath                   userPathSnapshot         `json:"previous_path"`
	PreviousAutoStart              gatewayAutoStartSnapshot `json:"previous_auto_start"`
	PreviousServices               serviceState             `json:"previous_services"`
	PreviousConnectors             []string                 `json:"previous_connectors,omitempty"`
	PreserveConnectorConfiguration bool                     `json:"preserve_connector_configuration,omitempty"`
	TargetConnector                string                   `json:"target_connector"`
	TargetMode                     string                   `json:"target_mode"`
	TargetServices                 serviceState             `json:"target_services"`
	FromVersion                    string                   `json:"from_version,omitempty"`
	TargetVersion                  string                   `json:"target_version,omitempty"`
	PreviousCodexHome              string                   `json:"previous_codex_home,omitempty"`
	PreviousClaudeConfigDir        string                   `json:"previous_claude_config_dir,omitempty"`
	CodexHome                      string                   `json:"codex_home,omitempty"`
	ClaudeConfigDir                string                   `json:"claude_config_dir,omitempty"`
	MaintenanceSHA256              string                   `json:"maintenance_sha256,omitempty"`
	DeleteUserData                 bool                     `json:"delete_user_data,omitempty"`
	UninstallPathEntryOwned        bool                     `json:"uninstall_path_entry_owned,omitempty"`
	UninstallPathSeparatorReused   bool                     `json:"uninstall_path_separator_reused,omitempty"`
	UninstallPathValueCreated      bool                     `json:"uninstall_path_value_created,omitempty"`
	HandoffFromInstall             string                   `json:"handoff_from_install,omitempty"`
	HandoffPreviousState           *installState            `json:"handoff_previous_state,omitempty"`
}

type published087SetupJournal struct {
	SchemaVersion int                          `json:"schema_version"`
	Phase         string                       `json:"phase"`
	Transaction   published087SetupTransaction `json:"transaction"`
}

func TestPublishedSetupJournalSchemaFixturesReproduceStrictCompatibilityBoundary(t *testing.T) {
	installRoot, dataRoot, maintenancePath := testTransactionRoots(t)
	transaction := testSetupTransactionForRoots("install", installRoot, dataRoot, maintenancePath, nil)
	// The shared transaction fixture follows current Setup behavior and
	// captures Antigravity's config home for every install. That field did not
	// exist in the published 0.8.7 schema whose strict boundary this fixture
	// reproduces, so remove it from the frozen legacy document.
	transaction.AntigravityConfigDir = ""

	published087 := setupJournal{
		SchemaVersion: setupJournalSchemaVersion,
		Phase:         setupPhaseComplete,
		Transaction:   transaction,
	}
	published087Bytes, err := json.Marshal(published087)
	if err != nil {
		t.Fatal(err)
	}
	var oldReader published087SetupJournal
	if err := decodeSetupJournalJSON(published087Bytes, &oldReader); err != nil {
		t.Fatalf("0.8.7 reader rejected its exact schema fixture: %v", err)
	}

	published088 := published087
	published088.Transaction.PreviousStableHookStatus = stableHookSnapshotInactive
	published088Bytes, err := json.Marshal(published088)
	if err != nil {
		t.Fatal(err)
	}
	err = decodeSetupJournalJSON(published088Bytes, &oldReader)
	if err == nil || !strings.Contains(err.Error(), `unknown field "previous_stable_hook_status"`) {
		t.Fatalf("0.8.7 reader error for 0.8.8 schema fixture = %v", err)
	}
	var currentReader setupJournal
	if err := decodeSetupJournalJSON(published088Bytes, &currentReader); err != nil {
		t.Fatalf("current reader rejected the exact 0.8.8 schema fixture: %v", err)
	}
}

func TestCompleteTransitionPublishesFrozenLegacyReadableTombstone(t *testing.T) {
	installRoot, dataRoot, maintenancePath := testTransactionRoots(t)
	transaction := testSetupTransactionForRoots("install", installRoot, dataRoot, maintenancePath, nil)
	transaction.PreviousStableHookStatus = stableHookSnapshotInactive
	expected := setupTransactionExpectations{
		InstallRoot: installRoot, DataRoot: dataRoot, MaintenancePath: maintenancePath,
	}
	path := filepath.Join(t.TempDir(), "private", "setup-transaction.json")
	journal := setupJournal{
		SchemaVersion: setupJournalSchemaVersion,
		Phase:         setupPhaseConverged,
		Transaction:   transaction,
	}
	if err := writeDurableJournal(path, journal, false); err != nil {
		t.Fatal(err)
	}

	if err := transitionSetupJournalToTerminalAtWithWriter(
		path,
		transaction,
		setupPhaseConverged,
		expected,
		writeDurableValue,
	); err != nil {
		t.Fatal(err)
	}
	data := readJournalFixtureBytes(t, path)
	if want := frozenTerminalSetupJournalBytes(t); !bytes.Equal(data, want) {
		t.Fatalf("terminal journal bytes = %q, want %q", data, want)
	}
	var oldReader published087SetupJournal
	if err := decodeSetupJournalJSON(data, &oldReader); err != nil {
		t.Fatalf("0.8.7 reader rejected frozen terminal journal: %v", err)
	}
	document, err := readSetupJournalDocument(path)
	if err != nil || document == nil || !document.Terminal ||
		document.Journal.Phase != setupPhaseComplete {
		t.Fatalf("terminal journal document = %+v, %v", document, err)
	}
}

func TestKnownCompletedJournalNormalizesOnceAndPreservesTerminalBytes(t *testing.T) {
	installRoot, dataRoot, maintenancePath := testTransactionRoots(t)
	transaction := testSetupTransactionForRoots("install", installRoot, dataRoot, maintenancePath, nil)
	transaction.PreviousStableHookStatus = stableHookSnapshotInactive
	expected := setupTransactionExpectations{
		InstallRoot: installRoot, DataRoot: dataRoot, MaintenancePath: maintenancePath,
	}
	path := filepath.Join(t.TempDir(), "private", "setup-transaction.json")
	if err := writeDurableJournal(path, setupJournal{
		SchemaVersion: setupJournalSchemaVersion,
		Phase:         setupPhaseComplete,
		Transaction:   transaction,
	}, false); err != nil {
		t.Fatal(err)
	}

	normalized, err := normalizeCompletedSetupJournalAt(path, expected)
	if err != nil || !normalized {
		t.Fatalf("normalize known completed journal = %t, %v", normalized, err)
	}
	want := frozenTerminalSetupJournalBytes(t)
	if got := readJournalFixtureBytes(t, path); !bytes.Equal(got, want) {
		t.Fatalf("normalized terminal bytes = %q, want %q", got, want)
	}
	normalized, err = normalizeCompletedSetupJournalAt(path, expected)
	if err != nil || normalized {
		t.Fatalf("repeat terminal normalization = %t, %v", normalized, err)
	}
	if got := readJournalFixtureBytes(t, path); !bytes.Equal(got, want) {
		t.Fatal("repeat terminal normalization changed frozen bytes")
	}
}

func TestSetupRecoveryEntryPointsNormalizeKnownCompletedJournal(t *testing.T) {
	tests := []struct {
		name string
		run  func(string, setupTransactionExpectations) error
	}{
		{
			name: "install or repair recovery",
			run: func(path string, expected setupTransactionExpectations) error {
				return recoverSetupTransactionAt(path, expected, setupRecoveryOps{})
			},
		},
		{
			name: "uninstall recovery",
			run: func(path string, expected setupTransactionExpectations) error {
				_, err := preparePendingSetupTransactionForUninstallAt(
					path,
					expected,
					uninstallRecoveryOps{},
				)
				return err
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			installRoot, dataRoot, maintenancePath := testTransactionRoots(t)
			transaction := testSetupTransactionForRoots("install", installRoot, dataRoot, maintenancePath, nil)
			transaction.PreviousStableHookStatus = stableHookSnapshotInactive
			expected := setupTransactionExpectations{
				InstallRoot: installRoot, DataRoot: dataRoot, MaintenancePath: maintenancePath,
			}
			path := filepath.Join(t.TempDir(), "private", "setup-transaction.json")
			if err := writeDurableJournal(path, setupJournal{
				SchemaVersion: setupJournalSchemaVersion,
				Phase:         setupPhaseComplete,
				Transaction:   transaction,
			}, false); err != nil {
				t.Fatal(err)
			}
			if err := test.run(path, expected); err != nil {
				t.Fatal(err)
			}
			if got, want := readJournalFixtureBytes(t, path), frozenTerminalSetupJournalBytes(t); !bytes.Equal(got, want) {
				t.Fatalf("entry-point terminal bytes = %q, want %q", got, want)
			}
		})
	}
}

func TestCompletedJournalNormalizationRejectsUnsafeStateWithoutChangingBytes(t *testing.T) {
	tests := []struct {
		name    string
		phase   string
		schema  int
		mutate  func(map[string]any)
		raw     []byte
		wantErr bool
	}{
		{name: "pending", phase: setupPhaseIntent, schema: setupJournalSchemaVersion},
		{name: "deferred cleanup", phase: setupPhaseConverged, schema: setupJournalSchemaVersion},
		{name: "unknown schema", phase: setupPhaseComplete, schema: setupJournalSchemaVersion + 1, wantErr: true},
		{name: "failed phase", phase: "failed", schema: setupJournalSchemaVersion, wantErr: true},
		{
			name: "unknown pending field", phase: setupPhaseIntent, schema: setupJournalSchemaVersion,
			mutate: func(document map[string]any) {
				document["transaction"].(map[string]any)["future_recovery_authority"] = true
			},
			wantErr: true,
		},
		{
			name: "unknown complete field", phase: setupPhaseComplete, schema: setupJournalSchemaVersion,
			mutate: func(document map[string]any) {
				document["transaction"].(map[string]any)["future_recovery_authority"] = true
			},
			wantErr: true,
		},
		{name: "malformed", raw: []byte(`{"schema_version":2,"phase":"complete"` + "\n"), wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			installRoot, dataRoot, maintenancePath := testTransactionRoots(t)
			transaction := testSetupTransactionForRoots("install", installRoot, dataRoot, maintenancePath, nil)
			transaction.PreviousStableHookStatus = stableHookSnapshotInactive
			expected := setupTransactionExpectations{
				InstallRoot: installRoot, DataRoot: dataRoot, MaintenancePath: maintenancePath,
			}
			path := filepath.Join(t.TempDir(), "private", "setup-transaction.json")
			if err := writeDurableJournal(path, setupJournal{
				SchemaVersion: setupJournalSchemaVersion,
				Phase:         setupPhaseComplete,
				Transaction:   transaction,
			}, false); err != nil {
				t.Fatal(err)
			}
			var fixture []byte
			if test.raw != nil {
				fixture = test.raw
			} else {
				document := map[string]any{}
				if err := json.Unmarshal(readJournalFixtureBytes(t, path), &document); err != nil {
					t.Fatal(err)
				}
				document["schema_version"] = test.schema
				document["phase"] = test.phase
				if test.mutate != nil {
					test.mutate(document)
				}
				var err error
				fixture, err = json.MarshalIndent(document, "", "  ")
				if err != nil {
					t.Fatal(err)
				}
				fixture = append(fixture, '\n')
			}
			if err := os.WriteFile(path, fixture, 0o600); err != nil {
				t.Fatal(err)
			}

			normalized, err := normalizeCompletedSetupJournalAt(path, expected)
			if test.wantErr && (err == nil || normalized) {
				t.Fatalf("unsafe normalization = %t, %v", normalized, err)
			} else if !test.wantErr && (err != nil || normalized) {
				t.Fatalf("inactive normalization = %t, %v", normalized, err)
			}
			if test.wantErr && !strings.Contains(
				err.Error(),
				"run the current authenticated Windows rescue or a newer DefenseClaw Setup",
			) {
				t.Fatalf("unsafe normalization guidance = %v", err)
			}
			if got := readJournalFixtureBytes(t, path); !bytes.Equal(got, fixture) {
				t.Fatal("refused normalization changed journal bytes")
			}
		})
	}
}

func TestCompletedJournalNormalizationRejectsTamperedTransactionAndUnsafeDACL(t *testing.T) {
	t.Run("tampered transaction", func(t *testing.T) {
		installRoot, dataRoot, maintenancePath := testTransactionRoots(t)
		transaction := testSetupTransactionForRoots("install", installRoot, dataRoot, maintenancePath, nil)
		transaction.PreviousStableHookStatus = stableHookSnapshotInactive
		expected := setupTransactionExpectations{
			InstallRoot: installRoot, DataRoot: dataRoot, MaintenancePath: maintenancePath,
		}
		transaction.InstallRoot = filepath.Join(t.TempDir(), "unrelated")
		path := filepath.Join(t.TempDir(), "private", "setup-transaction.json")
		if err := writeDurableJournal(path, setupJournal{
			SchemaVersion: setupJournalSchemaVersion,
			Phase:         setupPhaseComplete,
			Transaction:   transaction,
		}, false); err != nil {
			t.Fatal(err)
		}
		before := readJournalFixtureBytes(t, path)
		if normalized, err := normalizeCompletedSetupJournalAt(path, expected); err == nil || normalized {
			t.Fatalf("tampered normalization = %t, %v", normalized, err)
		}
		if after := readJournalFixtureBytes(t, path); !bytes.Equal(after, before) {
			t.Fatal("tampered normalization changed journal bytes")
		}
	})

	t.Run("unsafe DACL", func(t *testing.T) {
		installRoot, dataRoot, maintenancePath := testTransactionRoots(t)
		transaction := testSetupTransactionForRoots("install", installRoot, dataRoot, maintenancePath, nil)
		transaction.PreviousStableHookStatus = stableHookSnapshotInactive
		expected := setupTransactionExpectations{
			InstallRoot: installRoot, DataRoot: dataRoot, MaintenancePath: maintenancePath,
		}
		path := filepath.Join(t.TempDir(), "private", "setup-transaction.json")
		if err := writeDurableJournal(path, setupJournal{
			SchemaVersion: setupJournalSchemaVersion,
			Phase:         setupPhaseComplete,
			Transaction:   transaction,
		}, false); err != nil {
			t.Fatal(err)
		}
		before := readJournalFixtureBytes(t, path)
		grantUntrustedJournalWriteForTest(t, path)
		if normalized, err := normalizeCompletedSetupJournalAt(path, expected); err == nil || normalized {
			t.Fatalf("unsafe-DACL normalization = %t, %v", normalized, err)
		}
		if after := readJournalFixtureBytes(t, path); !bytes.Equal(after, before) {
			t.Fatal("unsafe-DACL normalization changed journal bytes")
		}
	})
}

func frozenTerminalSetupJournalBytes(t *testing.T) []byte {
	t.Helper()
	return []byte("{\n  \"schema_version\": 2,\n  \"phase\": \"complete\"\n}\n")
}

func readJournalFixtureBytes(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func grantUntrustedJournalWriteForTest(t *testing.T, path string) {
	t.Helper()
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
		t.Fatalf("current token user: %v", err)
	}
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		t.Fatal(err)
	}
	everyone, err := windows.CreateWellKnownSid(windows.WinWorldSid)
	if err != nil {
		t.Fatal(err)
	}
	entry := func(sid *windows.SID, sidType windows.TRUSTEE_TYPE, mask windows.ACCESS_MASK) windows.EXPLICIT_ACCESS {
		return windows.EXPLICIT_ACCESS{
			AccessPermissions: mask,
			AccessMode:        windows.GRANT_ACCESS,
			Inheritance:       windows.NO_INHERITANCE,
			Trustee: windows.TRUSTEE{
				TrusteeForm:  windows.TRUSTEE_IS_SID,
				TrusteeType:  sidType,
				TrusteeValue: windows.TrusteeValueFromSID(sid),
			},
		}
	}
	acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{
		entry(user.User.Sid, windows.TRUSTEE_IS_USER, windows.GENERIC_ALL),
		entry(system, windows.TRUSTEE_IS_WELL_KNOWN_GROUP, windows.GENERIC_ALL),
		entry(everyone, windows.TRUSTEE_IS_WELL_KNOWN_GROUP, windows.GENERIC_WRITE),
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil,
		nil,
		acl,
		nil,
	); err != nil {
		t.Fatal(err)
	}
}

func TestPrivateTransactionOwnerGateRejectsForeignSID(t *testing.T) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
		t.Fatalf("current token user: %v", err)
	}
	if err := validatePrivateTransactionOwner("owned-journal-fixture", user.User.Sid, user.User.Sid); err != nil {
		t.Fatalf("current-user owner rejected: %v", err)
	}
	foreign, err := windows.CreateWellKnownSid(windows.WinWorldSid)
	if err != nil {
		t.Fatal(err)
	}
	if err := validatePrivateTransactionOwner("unowned-journal-fixture", foreign, user.User.Sid); err == nil {
		t.Fatal("foreign journal owner accepted")
	}
}

func TestTerminalPublicationReportsAmbiguousLateReplacementWithoutFullCompleteState(t *testing.T) {
	installRoot, dataRoot, maintenancePath := testTransactionRoots(t)
	transaction := testSetupTransactionForRoots("install", installRoot, dataRoot, maintenancePath, nil)
	transaction.PreviousStableHookStatus = stableHookSnapshotInactive
	expected := setupTransactionExpectations{
		InstallRoot: installRoot, DataRoot: dataRoot, MaintenancePath: maintenancePath,
	}
	path := filepath.Join(t.TempDir(), "private", "setup-transaction.json")
	if err := writeDurableJournal(path, setupJournal{
		SchemaVersion: setupJournalSchemaVersion,
		Phase:         setupPhaseConverged,
		Transaction:   transaction,
	}, false); err != nil {
		t.Fatal(err)
	}
	lateFailure := errors.New("simulated write-through failure after terminal publication")
	write := func(path string, value any, replace bool) error {
		return writeDurableValueWithRename(path, value, replace, func(source, destination string) error {
			if err := replaceDurableFile(source, destination); err != nil {
				return err
			}
			return lateFailure
		})
	}
	err := transitionSetupJournalToTerminalAtWithWriter(
		path,
		transaction,
		setupPhaseConverged,
		expected,
		write,
	)
	if !errors.Is(err, errSetupJournalDurabilityAmbiguous) {
		t.Fatalf("terminal publication error = %v, want ambiguous durability", err)
	}
	if got, want := readJournalFixtureBytes(t, path), frozenTerminalSetupJournalBytes(t); !bytes.Equal(got, want) {
		t.Fatalf("visible ambiguous terminal bytes = %q, want %q", got, want)
	}
}
