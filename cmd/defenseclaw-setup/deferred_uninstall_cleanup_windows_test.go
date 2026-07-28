// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package main

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/hookruntime"
	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

const (
	deferredCleanupBootOne = "00112233-4455-6677-8899-aabbccddeeff"
	deferredCleanupBootTwo = "ffeeddcc-bbaa-9988-7766-554433221100"
)

type deferredCleanupFixture struct {
	record      deferredUninstallCleanupRecord
	state       hookruntime.State
	journal     setupJournal
	maintenance string
}

func TestDeferredCleanupTransactionRootExpectationFailsClosed(t *testing.T) {
	transaction := setupTransaction{
		InstallRoot:     filepath.Join(t.TempDir(), "Programs", "DefenseClaw"),
		DataRoot:        filepath.Join(t.TempDir(), ".defenseclaw"),
		MaintenancePath: filepath.Join(t.TempDir(), setupArtifactName),
	}
	arm, err := defaultDeferredCleanupTransactionRootExpectation(transaction)
	if err == nil || arm || !strings.Contains(err.Error(), "do not match") {
		t.Fatalf("root expectation = arm %t, error %v", arm, err)
	}
}

func newDeferredCleanupFixture(t *testing.T) deferredCleanupFixture {
	t.Helper()
	productRoot := filepath.Join(t.TempDir(), "DefenseClaw")
	runtimeRoot := filepath.Join(productRoot, "HookRuntime")
	stateRoot := filepath.Join(productRoot, "InstallerState")
	cacheRoot := filepath.Join(productRoot, "InstallerCache")
	for _, directory := range []string{runtimeRoot, stateRoot, cacheRoot} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := safefile.ProtectDirectory(directory); err != nil {
			t.Fatal(err)
		}
	}

	launcherPath := filepath.Join(runtimeRoot, hookruntime.LauncherName)
	if err := os.WriteFile(launcherPath, unsignedTestPE(), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := safefile.ProtectFile(launcherPath); err != nil {
		t.Fatal(err)
	}
	launcherDigest, err := fileSHA256(launcherPath)
	if err != nil {
		t.Fatal(err)
	}
	launcherInfo, err := os.Stat(launcherPath)
	if err != nil {
		t.Fatal(err)
	}
	transactionID := "0123456789abcdef0123456789abcdef"
	hookPath := filepath.Join(productRoot, "Programs", "DefenseClaw", "bin", hookruntime.LauncherName)
	statePath := filepath.Join(runtimeRoot, hookruntime.StateName)
	state := hookruntime.State{
		SchemaVersion:  hookruntime.SchemaVersion,
		Status:         hookruntime.StatusDisabled,
		RuntimeRoot:    runtimeRoot,
		LauncherPath:   launcherPath,
		LauncherSHA256: launcherDigest,
		LauncherKind:   hookruntime.LauncherKindTrampoline,
		HookPath:       hookPath,
		HookSHA256:     strings.Repeat("a", 64),
		TransactionID:  transactionID,
	}
	writeDeferredCleanupHookState(t, statePath, state)

	maintenance := filepath.Join(cacheRoot, setupArtifactName)
	if err := os.WriteFile(maintenance, []byte("fixture setup"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := safefile.ProtectFile(maintenance); err != nil {
		t.Fatal(err)
	}
	maintenanceDigest, err := fileSHA256(maintenance)
	if err != nil {
		t.Fatal(err)
	}
	recordPath := deferredUninstallCleanupPath(stateRoot)
	record := deferredUninstallCleanupRecord{
		SchemaVersion:           deferredUninstallCleanupSchemaVersion,
		Status:                  deferredCleanupStatusPending,
		TransactionID:           transactionID,
		UninstallBootIdentifier: deferredCleanupBootOne,
		RuntimeRoot:             runtimeRoot,
		LauncherPath:            launcherPath,
		StatePath:               statePath,
		RetiredLauncherPath:     retiredHookRuntimePath(launcherPath, transactionID),
		RetiredStatePath:        retiredHookRuntimePath(statePath, transactionID),
		LauncherSHA256:          launcherDigest,
		LauncherSize:            launcherInfo.Size(),
		LauncherKind:            hookruntime.LauncherKindTrampoline,
		HookPath:                hookPath,
		HookSHA256:              state.HookSHA256,
		UnsignedLocalArtifact:   true,
		MaintenancePath:         maintenance,
		MaintenanceSHA256:       maintenanceDigest,
		InstallerStateRoot:      stateRoot,
		JournalPath:             journalPaths(stateRoot).Journal,
		RecordPath:              recordPath,
		CacheAckPath:            deferredUninstallCleanupAckPath(maintenance),
		RunValueName:            deferredCleanupRunValueName,
		RunCommand:              `"fixture setup" /cleanup`,
	}
	if err := writeDurableValue(recordPath, record, false); err != nil {
		t.Fatal(err)
	}
	journal := setupJournal{
		SchemaVersion: setupJournalSchemaVersion,
		Phase:         setupPhaseConverged,
		Transaction: setupTransaction{
			SchemaVersion:   setupTransactionSchemaVersion,
			ID:              transactionID,
			Action:          "uninstall",
			MaintenancePath: maintenance,
		},
	}
	if err := writeDurableValue(record.JournalPath, journal, false); err != nil {
		t.Fatal(err)
	}
	return deferredCleanupFixture{
		record:      record,
		state:       state,
		journal:     journal,
		maintenance: maintenance,
	}
}

func writeDeferredCleanupHookState(t *testing.T, path string, state hookruntime.State) {
	t.Helper()
	body, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	body = append(body, '\n')
	if err := safefile.WritePrivate(path, body); err != nil {
		t.Fatal(err)
	}
}

func replaceDeferredCleanupRecord(t *testing.T, record deferredUninstallCleanupRecord) {
	t.Helper()
	if err := writeDurableValue(record.RecordPath, record, true); err != nil {
		t.Fatal(err)
	}
}

func TestDeferredCleanupBootTransitionRejectsSameBootAndHibernateResume(t *testing.T) {
	record := deferredUninstallCleanupRecord{UninstallBootIdentifier: deferredCleanupBootOne}
	for _, name := range []string{"same-boot", "hibernate-resume"} {
		t.Run(name, func(t *testing.T) {
			if err := validateDeferredCleanupBootTransition(record, deferredCleanupBootOne); !errors.Is(err, errUninstallCleanupRequiresRestart) {
				t.Fatalf("boot transition error = %v", err)
			}
		})
	}
	if err := validateDeferredCleanupBootTransition(record, deferredCleanupBootTwo); err != nil {
		t.Fatalf("genuine boot transition rejected: %v", err)
	}
}

func TestDeferredCleanupRejectsMissingHookRuntimeBeforeLegacyPostExitPath(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "HookRuntime")
	err := requireDeferredCleanupHookRuntime(missing)
	if err == nil || !strings.Contains(err.Error(), "unsupported legacy cache cleanup") {
		t.Fatalf("missing HookRuntime error = %v", err)
	}
}

func TestRetireDisabledHookRuntimeAcknowledgesBeforeExactDeletion(t *testing.T) {
	fixture := newDeferredCleanupFixture(t)
	if err := retireDisabledHookRuntime(&fixture.record, deferredCleanupBootTwo); err != nil {
		t.Fatalf("retire disabled HookRuntime: %v", err)
	}
	if fixture.record.Status != deferredCleanupStatusRuntimeRetired ||
		fixture.record.CleanupBootIdentifier != deferredCleanupBootTwo {
		t.Fatalf("runtime retirement acknowledgement = %+v", fixture.record)
	}
	if _, err := os.Lstat(fixture.record.RuntimeRoot); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("HookRuntime survived exact retirement: %v", err)
	}
	stored, err := readDeferredUninstallCleanupRecord(fixture.record.RecordPath)
	if err != nil || stored == nil ||
		stored.Status != deferredCleanupStatusRuntimeRetired ||
		stored.CleanupBootIdentifier != deferredCleanupBootTwo {
		t.Fatalf("durable retirement acknowledgement = %+v, error %v", stored, err)
	}
}

func TestRetireDisabledHookRuntimeResumesAfterDurableAcknowledgementCrash(t *testing.T) {
	for _, tc := range []struct {
		name               string
		deleteRetiredState bool
	}{
		{name: "before exact deletion"},
		{name: "after partial exact deletion", deleteRetiredState: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fixture := newDeferredCleanupFixture(t)
			injected := errors.New("injected crash after durable acknowledgement")
			err := retireDisabledHookRuntimeWithAfterAck(
				&fixture.record,
				deferredCleanupBootTwo,
				func() error { return injected },
			)
			if !errors.Is(err, injected) {
				t.Fatalf("retirement error = %v, want injected crash", err)
			}
			stored, readErr := readDeferredUninstallCleanupRecord(fixture.record.RecordPath)
			if readErr != nil || stored == nil ||
				stored.Status != deferredCleanupStatusRuntimeRetired ||
				stored.CleanupBootIdentifier != deferredCleanupBootTwo {
				t.Fatalf("durable retirement acknowledgement = %+v, error %v", stored, readErr)
			}
			for _, path := range []string{
				fixture.record.RetiredLauncherPath,
				fixture.record.RetiredStatePath,
			} {
				if _, statErr := os.Lstat(path); statErr != nil {
					t.Fatalf("acknowledged retired path missing before resume: %s: %v", path, statErr)
				}
			}
			if tc.deleteRetiredState {
				if err := deletePrivatePathByHandle(fixture.record.RetiredStatePath, false); err != nil {
					t.Fatalf("simulate partial exact deletion: %v", err)
				}
			}
			if err := retireDisabledHookRuntime(&fixture.record, deferredCleanupBootTwo); err != nil {
				t.Fatalf("resume acknowledged HookRuntime retirement: %v", err)
			}
			if _, err := os.Lstat(fixture.record.RuntimeRoot); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("HookRuntime survived acknowledged retirement resume: %v", err)
			}
		})
	}
}

func TestRetireDisabledHookRuntimeRefusesTamperArchitectureSignerTransactionAndDACL(t *testing.T) {
	for _, test := range []struct {
		name  string
		drift func(*testing.T, *deferredCleanupFixture)
	}{
		{
			name: "digest",
			drift: func(t *testing.T, fixture *deferredCleanupFixture) {
				body, err := os.ReadFile(fixture.record.LauncherPath)
				if err != nil {
					t.Fatal(err)
				}
				body[len(body)-1] ^= 0xff
				if err := os.WriteFile(fixture.record.LauncherPath, body, 0o700); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "architecture",
			drift: func(t *testing.T, fixture *deferredCleanupFixture) {
				body := unsignedTestPE()
				binary.LittleEndian.PutUint16(body[0x84:0x86], 0xaa64)
				if err := os.WriteFile(fixture.record.LauncherPath, body, 0o700); err != nil {
					t.Fatal(err)
				}
				digest, err := fileSHA256(fixture.record.LauncherPath)
				if err != nil {
					t.Fatal(err)
				}
				fixture.record.LauncherSHA256 = digest
				fixture.state.LauncherSHA256 = digest
				writeDeferredCleanupHookState(t, fixture.record.StatePath, fixture.state)
				replaceDeferredCleanupRecord(t, fixture.record)
			},
		},
		{
			name: "signer",
			drift: func(t *testing.T, fixture *deferredCleanupFixture) {
				fixture.record.LauncherSigned = true
				fixture.record.UnsignedLocalArtifact = false
				fixture.record.SignerThumbprintSHA256 = strings.Repeat("b", 64)
				replaceDeferredCleanupRecord(t, fixture.record)
			},
		},
		{
			name: "transaction",
			drift: func(t *testing.T, fixture *deferredCleanupFixture) {
				fixture.state.TransactionID = "fedcba9876543210fedcba9876543210"
				writeDeferredCleanupHookState(t, fixture.record.StatePath, fixture.state)
			},
		},
		{
			name: "dacl",
			drift: func(t *testing.T, fixture *deferredCleanupFixture) {
				addSetupReadOnlyDACLDrift(t, fixture.record.LauncherPath)
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newDeferredCleanupFixture(t)
			test.drift(t, &fixture)
			if err := retireDisabledHookRuntime(&fixture.record, deferredCleanupBootTwo); err == nil {
				t.Fatal("unsafe HookRuntime cleanup succeeded")
			}
			if _, err := os.Lstat(fixture.record.RuntimeRoot); err != nil {
				t.Fatalf("refused cleanup removed HookRuntime: %v", err)
			}
			stored, err := readDeferredUninstallCleanupRecord(fixture.record.RecordPath)
			if err != nil || stored == nil || stored.Status != deferredCleanupStatusPending {
				t.Fatalf("refused cleanup changed durable record: %+v, error %v", stored, err)
			}
		})
	}
}

func TestRetireDisabledHookRuntimeRejectsReparseIdentity(t *testing.T) {
	fixture := newDeferredCleanupFixture(t)
	alias := filepath.Join(t.TempDir(), "HookRuntime")
	output, err := newCapturedSetupCommand(
		t.Context(),
		"cmd.exe",
		"/d",
		"/c",
		"mklink",
		"/J",
		alias,
		fixture.record.RuntimeRoot,
	).CombinedOutput()
	if err != nil {
		t.Skipf("junction creation unavailable: %v (%s)", err, output)
	}
	defer os.Remove(alias)
	fixture.record.RuntimeRoot = alias
	fixture.record.LauncherPath = filepath.Join(alias, hookruntime.LauncherName)
	fixture.record.StatePath = filepath.Join(alias, hookruntime.StateName)
	fixture.record.RetiredLauncherPath = retiredHookRuntimePath(fixture.record.LauncherPath, fixture.record.TransactionID)
	fixture.record.RetiredStatePath = retiredHookRuntimePath(fixture.record.StatePath, fixture.record.TransactionID)
	if err := retireDisabledHookRuntime(&fixture.record, deferredCleanupBootTwo); err == nil {
		t.Fatal("reparse HookRuntime cleanup succeeded")
	}
	if _, err := os.Lstat(filepath.Join(fixture.state.RuntimeRoot, hookruntime.LauncherName)); err != nil {
		t.Fatalf("reparse refusal removed canonical launcher: %v", err)
	}
}

func TestFinishDeferredInstallerStateCleanupDeletesOnlyTerminalOwnedEntries(t *testing.T) {
	fixture := newDeferredCleanupFixture(t)
	if err := retireDisabledHookRuntime(&fixture.record, deferredCleanupBootTwo); err != nil {
		t.Fatal(err)
	}
	setupLog := filepath.Join(fixture.record.InstallerStateRoot, "setup.log")
	if err := safefile.WritePrivate(setupLog, []byte("terminal log\n")); err != nil {
		t.Fatal(err)
	}
	finalizerCalls := 0
	if err := finishDeferredInstallerStateCleanupWith(
		fixture.record,
		func(deferredUninstallCleanupRecord) error { return nil },
		func(got deferredUninstallCleanupRecord, pid int) error {
			finalizerCalls++
			if !reflectDeferredCleanupRecordsEqual(got, fixture.record) || pid <= 0 {
				t.Fatalf("finalizer handoff = %+v, pid %d", got, pid)
			}
			return nil
		},
	); err != nil {
		t.Fatalf("finish installer state cleanup: %v", err)
	}
	if finalizerCalls != 1 {
		t.Fatalf("finalizer calls = %d, want 1", finalizerCalls)
	}
	if _, err := os.Lstat(fixture.record.InstallerStateRoot); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("InstallerState survived terminal cleanup: %v", err)
	}
	ack, err := readDeferredUninstallCleanupRecord(fixture.record.CacheAckPath)
	if err != nil || ack == nil || !reflectDeferredCleanupRecordsEqual(*ack, fixture.record) {
		t.Fatalf("cache acknowledgement = %+v, error %v", ack, err)
	}
	if _, err := os.Stat(fixture.maintenance); err != nil {
		t.Fatalf("maintenance executable was removed before post-process finalization: %v", err)
	}
}

func TestFinishDeferredInstallerStateCleanupResumesFromCacheAcknowledgement(t *testing.T) {
	fixture := newDeferredCleanupFixture(t)
	if err := retireDisabledHookRuntime(&fixture.record, deferredCleanupBootTwo); err != nil {
		t.Fatal(err)
	}
	injected := errors.New("injected finalizer start failure")
	err := finishDeferredInstallerStateCleanupWith(
		fixture.record,
		func(deferredUninstallCleanupRecord) error { return nil },
		func(deferredUninstallCleanupRecord, int) error { return injected },
	)
	if !errors.Is(err, injected) {
		t.Fatalf("finish error = %v, want injected finalizer failure", err)
	}
	if _, err := os.Lstat(fixture.record.InstallerStateRoot); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("InstallerState survived acknowledged retirement: %v", err)
	}
	if ack, err := readDeferredUninstallCleanupRecord(fixture.record.CacheAckPath); err != nil ||
		ack == nil || !reflectDeferredCleanupRecordsEqual(*ack, fixture.record) {
		t.Fatalf("cache acknowledgement = %+v, error %v", ack, err)
	}
	finalizerCalls := 0
	if err := finishDeferredInstallerStateCleanupWith(
		fixture.record,
		func(deferredUninstallCleanupRecord) error { return nil },
		func(deferredUninstallCleanupRecord, int) error {
			finalizerCalls++
			return nil
		},
	); err != nil {
		t.Fatalf("resume finalizer from cache acknowledgement: %v", err)
	}
	if finalizerCalls != 1 {
		t.Fatalf("resumed finalizer calls = %d, want 1", finalizerCalls)
	}
}

func reflectDeferredCleanupRecordsEqual(left, right deferredUninstallCleanupRecord) bool {
	leftJSON, _ := json.Marshal(left)
	rightJSON, _ := json.Marshal(right)
	return string(leftJSON) == string(rightJSON)
}

func TestFinishDeferredInstallerStateCleanupPreservesPendingFailedAndUnknownResidue(t *testing.T) {
	for _, test := range []struct {
		name  string
		drift func(*testing.T, *deferredCleanupFixture)
	}{
		{
			name: "pending-journal",
			drift: func(t *testing.T, fixture *deferredCleanupFixture) {
				fixture.journal.Phase = setupPhaseIntent
				if err := writeDurableValue(fixture.record.JournalPath, fixture.journal, true); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "failed-reconciliation",
			drift: func(t *testing.T, fixture *deferredCleanupFixture) {
				path := filepath.Join(fixture.record.InstallerStateRoot, connectorReconciliationFileName)
				if err := safefile.WritePrivate(path, []byte("{}\n")); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "unknown-entry",
			drift: func(t *testing.T, fixture *deferredCleanupFixture) {
				path := filepath.Join(fixture.record.InstallerStateRoot, "foreign.txt")
				if err := safefile.WritePrivate(path, []byte("preserve\n")); err != nil {
					t.Fatal(err)
				}
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newDeferredCleanupFixture(t)
			if err := retireDisabledHookRuntime(&fixture.record, deferredCleanupBootTwo); err != nil {
				t.Fatal(err)
			}
			test.drift(t, &fixture)
			if err := finishDeferredInstallerStateCleanupWith(
				fixture.record,
				func(deferredUninstallCleanupRecord) error { return nil },
				func(deferredUninstallCleanupRecord, int) error { return nil },
			); err == nil {
				t.Fatal("unsafe installer-state cleanup succeeded")
			}
			if _, err := os.Stat(fixture.record.RecordPath); err != nil {
				t.Fatalf("failed cleanup did not preserve durable record: %v", err)
			}
			if _, err := os.Stat(fixture.record.InstallerStateRoot); err != nil {
				t.Fatalf("failed cleanup removed InstallerState: %v", err)
			}
		})
	}
}

func TestReinstallSupersedesCleanupWithoutDeletingNewRuntimeState(t *testing.T) {
	fixture := newDeferredCleanupFixture(t)
	removedCommand := ""
	if err := markDeferredCleanupSuperseded(&fixture.record); err != nil {
		t.Fatalf("mark deferred cleanup superseded: %v", err)
	}
	if err := removeSupersededDeferredCleanupRecord(
		&fixture.record,
		func(command string) error {
			removedCommand = command
			return nil
		},
	); err != nil {
		t.Fatalf("supersede deferred cleanup: %v", err)
	}
	if removedCommand != fixture.record.RunCommand {
		t.Fatalf("removed startup command = %q", removedCommand)
	}
	if _, err := os.Stat(fixture.record.LauncherPath); err != nil {
		t.Fatalf("supersession deleted the launcher a reinstall will replace: %v", err)
	}
	if _, err := os.Stat(fixture.record.StatePath); err != nil {
		t.Fatalf("supersession deleted the state a reinstall will replace: %v", err)
	}
	if _, err := os.Lstat(fixture.record.RecordPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("superseded cleanup record survived: %v", err)
	}
}

func TestReinstallSupersessionResumesAcrossDurableCrashBoundaries(t *testing.T) {
	for _, test := range []struct {
		name            string
		afterSuperseded bool
	}{
		{name: "after superseded record", afterSuperseded: true},
		{name: "after terminal tombstone"},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newDeferredCleanupFixture(t)
			terminalizations := 0
			removals := 0
			ops := deferredCleanupSupersessionOps{
				validateJournal: func(
					deferredUninstallCleanupRecord,
					hookruntime.Paths,
					setupJournal,
				) error {
					return nil
				},
				terminalize: func(transaction setupTransaction) error {
					if transaction.ID != fixture.record.TransactionID {
						t.Fatalf("terminalized transaction = %q", transaction.ID)
					}
					terminalizations++
					return writeDurableValue(
						fixture.record.JournalPath,
						frozenTerminalSetupJournal(),
						true,
					)
				},
				remove: func(record *deferredUninstallCleanupRecord) error {
					removals++
					return removeSupersededDeferredCleanupRecord(
						record,
						func(string) error { return nil },
					)
				},
			}
			injected := errors.New("injected supersession crash")
			var afterRecord func() error
			var afterTerminal func() error
			if test.afterSuperseded {
				afterRecord = func() error { return injected }
			} else {
				afterTerminal = func() error { return injected }
			}
			err := supersedeDeferredUninstallCleanupRecord(
				&fixture.record,
				hookruntime.Paths{},
				ops,
				afterRecord,
				afterTerminal,
			)
			if !errors.Is(err, injected) {
				t.Fatalf("supersession error = %v, want injected crash", err)
			}
			stored, readErr := readDeferredUninstallCleanupRecord(fixture.record.RecordPath)
			if readErr != nil || stored == nil ||
				stored.Status != deferredCleanupStatusSuperseded {
				t.Fatalf("durable superseded record = %+v, error %v", stored, readErr)
			}
			document, documentErr := readSetupJournalDocument(fixture.record.JournalPath)
			if documentErr != nil || document == nil {
				t.Fatalf("read supersession journal: %+v, %v", document, documentErr)
			}
			if test.afterSuperseded && document.Terminal {
				t.Fatal("journal terminalized before the injected post-record crash")
			}
			if !test.afterSuperseded && !document.Terminal {
				t.Fatal("terminal tombstone was not durable before the injected crash")
			}

			if err := supersedeDeferredUninstallCleanupRecord(
				stored,
				hookruntime.Paths{},
				ops,
				nil,
				nil,
			); err != nil {
				t.Fatalf("resume supersession: %v", err)
			}
			if terminalizations != 1 {
				t.Fatalf("terminalizations = %d, want 1", terminalizations)
			}
			if removals != 1 {
				t.Fatalf("removals = %d, want 1", removals)
			}
			if _, err := os.Lstat(fixture.record.RecordPath); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("superseded record survived completed resume: %v", err)
			}
			document, documentErr = readSetupJournalDocument(fixture.record.JournalPath)
			if documentErr != nil || document == nil || !document.Terminal {
				t.Fatalf("resumed journal = %+v, error %v", document, documentErr)
			}
		})
	}
}

func TestReinstallSupersessionRejectsLockedJournalAndRecordDrift(t *testing.T) {
	tests := []struct {
		name  string
		drift func(*testing.T, *deferredCleanupFixture)
	}{
		{
			name: "wrong phase",
			drift: func(t *testing.T, fixture *deferredCleanupFixture) {
				fixture.journal.Phase = setupPhaseIntent
				if err := writeDurableValue(
					fixture.record.JournalPath,
					fixture.journal,
					true,
				); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "wrong transaction",
			drift: func(t *testing.T, fixture *deferredCleanupFixture) {
				fixture.journal.Transaction.ID = strings.Repeat("f", 32)
				if err := writeDurableValue(
					fixture.record.JournalPath,
					fixture.journal,
					true,
				); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "record replacement",
			drift: func(t *testing.T, fixture *deferredCleanupFixture) {
				changed := fixture.record
				changed.RunCommand += " changed"
				replaceDeferredCleanupRecord(t, changed)
			},
		},
		{
			name: "terminal without superseded record",
			drift: func(t *testing.T, fixture *deferredCleanupFixture) {
				if err := writeDurableValue(
					fixture.record.JournalPath,
					frozenTerminalSetupJournal(),
					true,
				); err != nil {
					t.Fatal(err)
				}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newDeferredCleanupFixture(t)
			test.drift(t, &fixture)
			called := false
			ops := deferredCleanupSupersessionOps{
				validateJournal: func(
					deferredUninstallCleanupRecord,
					hookruntime.Paths,
					setupJournal,
				) error {
					return nil
				},
				terminalize: func(setupTransaction) error {
					called = true
					return nil
				},
				remove: func(*deferredUninstallCleanupRecord) error {
					called = true
					return nil
				},
			}
			if err := supersedeDeferredUninstallCleanupRecord(
				&fixture.record,
				hookruntime.Paths{},
				ops,
				nil,
				nil,
			); err == nil {
				t.Fatal("unsafe supersession succeeded")
			}
			if called {
				t.Fatal("unsafe supersession reached terminalization or removal")
			}
			stored, err := readDeferredUninstallCleanupRecord(fixture.record.RecordPath)
			if err != nil || stored == nil ||
				stored.Status != deferredCleanupStatusPending {
				t.Fatalf("refused supersession changed record = %+v, %v", stored, err)
			}
		})
	}
}

func TestDeferredCleanupFinalizerPowerShellParses(t *testing.T) {
	fixture := newDeferredCleanupFixture(t)
	powerShell, err := systemPowerShellPath()
	if err != nil {
		t.Fatal(err)
	}
	command := deferredCleanupFinalizerCommand(
		powerShell,
		fixture.record,
		2147483647,
		100*time.Millisecond,
	)
	script := command.Args[len(command.Args)-1]
	parser := newCapturedSetupCommand(
		t.Context(),
		powerShell,
		"-NoProfile",
		"-NonInteractive",
		"-Command",
		"[void][scriptblock]::Create([Console]::In.ReadToEnd())",
	)
	parser.Stdin = strings.NewReader(script)
	if output, err := parser.CombinedOutput(); err != nil {
		t.Fatalf("deferred cleanup finalizer PowerShell parse failed: %v: %s", err, output)
	}
}
