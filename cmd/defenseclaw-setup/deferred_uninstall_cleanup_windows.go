// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"time"
	"unsafe"

	"github.com/defenseclaw/defenseclaw/internal/hookruntime"
	"github.com/defenseclaw/defenseclaw/internal/safefile"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const (
	deferredCleanupRunKeyPath   = `Software\Microsoft\Windows\CurrentVersion\Run`
	deferredCleanupRunValueName = "DefenseClawDeferredUninstallCleanup"
	deferredCleanupFileLimit    = int64(4 << 20)
)

var (
	queryDeferredCleanupBootIdentifier = windowsBootIdentifier
	verifyDeferredCleanupConnectors    = verifyRemovedConnectorsAfterUninstall
	startDeferredCleanupFinalizer      = startDeferredCleanupFinalizerProcess
)

type systemBootEnvironmentInformation struct {
	BootIdentifier windows.GUID
	FirmwareType   uint32
	BootFlags      uint64
}

func windowsBootIdentifier() (string, error) {
	var info systemBootEnvironmentInformation
	var returned uint32
	if err := windows.NtQuerySystemInformation(
		windows.SystemBootEnvironmentInformation,
		unsafe.Pointer(&info),
		uint32(unsafe.Sizeof(info)),
		&returned,
	); err != nil {
		return "", fmt.Errorf("query Windows boot identifier: %w", err)
	}
	if returned != 0 && returned < uint32(unsafe.Sizeof(info)) {
		return "", errors.New("Windows boot identifier response was truncated")
	}
	return canonicalWindowsBootIdentifier(info.BootIdentifier.String())
}

func canonicalWindowsBootIdentifier(value string) (string, error) {
	identifier := strings.ToLower(value)
	if len(identifier) == 38 && identifier[0] == '{' && identifier[len(identifier)-1] == '}' {
		identifier = identifier[1 : len(identifier)-1]
	}
	if !validBootIdentifier(identifier) {
		return "", errors.New("Windows returned an invalid boot identifier")
	}
	return identifier, nil
}

func deferredCleanupRunCommand(maintenancePath, transactionID string) (string, error) {
	if !validSetupTransactionID(transactionID) {
		return "", errors.New("deferred cleanup startup command requires a valid transaction identity")
	}
	localAppData, err := winpath.CurrentUserKnownFolderPath(windows.FOLDERID_LocalAppData)
	if err != nil {
		return "", fmt.Errorf("resolve LocalAppData for deferred cleanup: %w", err)
	}
	executable := maintenancePath
	if compact, ok := compactRunPath(maintenancePath, localAppData, `%LOCALAPPDATA%`); ok {
		executable = compact
	}
	command := quote(executable) + " /cleanup /quiet CLEANUPTRANSACTION=" + transactionID
	if err := validateRunCommand(command); err != nil {
		return "", fmt.Errorf("configure %s startup registration: %w", deferredCleanupRunValueName, err)
	}
	return command, nil
}

func configureDeferredCleanupRunValue(command string) error {
	if err := validateRunCommand(command); err != nil {
		return err
	}
	key, _, err := registry.CreateKey(
		registry.CURRENT_USER,
		deferredCleanupRunKeyPath,
		registry.QUERY_VALUE|registry.SET_VALUE,
	)
	if err != nil {
		return err
	}
	defer key.Close()
	current, valueType, readErr := key.GetStringValue(deferredCleanupRunValueName)
	if readErr != nil && readErr != registry.ErrNotExist {
		return readErr
	}
	if readErr == nil && (current != command || valueType != registry.EXPAND_SZ) {
		return errors.New("refusing to replace an unrelated deferred uninstall cleanup startup registration")
	}
	if readErr != nil {
		if err := key.SetExpandStringValue(deferredCleanupRunValueName, command); err != nil {
			return err
		}
	}
	return flushRegistryKey(key)
}

func removeDeferredCleanupRunValue(command string) error {
	key, err := registry.OpenKey(
		registry.CURRENT_USER,
		deferredCleanupRunKeyPath,
		registry.QUERY_VALUE|registry.SET_VALUE,
	)
	if err == registry.ErrNotExist {
		return nil
	}
	if err != nil {
		return err
	}
	defer key.Close()
	current, valueType, readErr := key.GetStringValue(deferredCleanupRunValueName)
	if readErr == registry.ErrNotExist {
		return nil
	}
	if readErr != nil {
		return readErr
	}
	if current != command || valueType != registry.EXPAND_SZ {
		return errors.New("refusing to remove an unrelated deferred uninstall cleanup startup registration")
	}
	if err := key.DeleteValue(deferredCleanupRunValueName); err != nil && err != registry.ErrNotExist {
		return err
	}
	return flushRegistryKey(key)
}

var deferredCleanupTransactionRootExpectation = defaultDeferredCleanupTransactionRootExpectation

func defaultDeferredCleanupTransactionRootExpectation(
	transaction setupTransaction,
) (bool, error) {
	expectedInstallRoot, installErr := defaultInstallRoot()
	expectedDataRoot, dataErr := defaultDataRoot()
	expectedMaintenancePath, maintenanceErr := defaultMaintenancePath()
	if err := errors.Join(installErr, dataErr, maintenanceErr); err != nil {
		return false, err
	}
	if !samePath(transaction.InstallRoot, expectedInstallRoot) ||
		!samePath(transaction.DataRoot, expectedDataRoot) ||
		!samePath(transaction.MaintenancePath, expectedMaintenancePath) {
		return false, errors.New(
			"deferred uninstall cleanup transaction roots do not match current-user Known Folders",
		)
	}
	return true, nil
}

func armDeferredUninstallCleanup(transaction setupTransaction) error {
	arm, err := deferredCleanupTransactionRootExpectation(transaction)
	if err != nil {
		return err
	}
	if !arm {
		// The production expectation above never skips: this branch exists only
		// as an explicit seam for isolated transaction unit tests.
		return nil
	}
	paths, err := hookruntime.CurrentUserPaths()
	if err != nil {
		return err
	}
	if err := requireDeferredCleanupHookRuntime(paths.Root); err != nil {
		return err
	}
	transactionRoot, err := defaultTransactionRoot()
	if err != nil {
		return err
	}
	command, err := deferredCleanupRunCommand(transaction.MaintenancePath, transaction.ID)
	if err != nil {
		return err
	}
	bootIdentifier, err := queryDeferredCleanupBootIdentifier()
	if err != nil {
		return err
	}
	journalPath := journalPaths(transactionRoot).Journal
	journal, err := readSetupJournal(journalPath)
	if err != nil {
		return err
	}
	if journal == nil || journal.Phase != setupPhaseConverged ||
		!setupTransactionsEqual(journal.Transaction, transaction) {
		return errors.New("deferred uninstall cleanup requires the exact converged uninstall journal")
	}
	if err := connectorReconciliationPendingError("uninstall"); err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), setupExecutableReleaseTimeout)
	defer cancel()
	var record deferredUninstallCleanupRecord
	if err := hookruntime.WithGatewayStartLock(ctx, func() error {
		var buildErr error
		record, buildErr = buildDeferredUninstallCleanupRecord(
			transaction,
			paths,
			transactionRoot,
			command,
			bootIdentifier,
		)
		return buildErr
	}); err != nil {
		return fmt.Errorf("bind disabled HookRuntime cleanup identity: %w", err)
	}

	recordPath := deferredUninstallCleanupPath(transactionRoot)
	if current, readErr := readDeferredUninstallCleanupRecord(recordPath); readErr != nil {
		return readErr
	} else if current != nil {
		currentCommand, commandErr := deferredCleanupRunCommand(current.MaintenancePath, current.TransactionID)
		if commandErr != nil {
			return commandErr
		}
		if err := validateDeferredUninstallCleanupRecord(
			*current,
			paths,
			transactionRoot,
			transaction.MaintenancePath,
			deferredCleanupRunValueName,
			currentCommand,
		); err != nil {
			return err
		}
		if current.TransactionID != transaction.ID ||
			(current.Status != deferredCleanupStatusPending &&
				current.Status != deferredCleanupStatusSuperseded) {
			return errors.New("a different deferred uninstall cleanup must be completed or superseded first")
		}
		record.UninstallBootIdentifier = current.UninstallBootIdentifier
		record.Status = current.Status
		if !reflect.DeepEqual(*current, record) {
			return errors.New("existing deferred uninstall cleanup identity differs from the current transaction")
		}
		if current.Status == deferredCleanupStatusSuperseded {
			return errUninstallCleanupRequiresRestart
		}
	} else if err := writeDurableValue(recordPath, record, false); err != nil {
		return fmt.Errorf("persist deferred uninstall cleanup record: %w", err)
	}
	if err := configureDeferredCleanupRunValue(command); err != nil {
		return fmt.Errorf("arm deferred uninstall cleanup startup: %w", err)
	}
	return errUninstallCleanupRequiresRestart
}

func requireDeferredCleanupHookRuntime(path string) error {
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		// Every supported native installation publishes either the legacy full
		// launcher or the schema-2 trampoline under HookRuntime. Without that
		// authenticated residue there is no safe post-process authority after
		// the completed-journal tombstone discards its transaction body.
		return errors.New("disabled stable HookRuntime is missing; refusing unsupported legacy cache cleanup")
	} else if err != nil {
		return err
	}
	return nil
}

func authenticatedUninstallMaintenanceDigest(transaction setupTransaction) (string, error) {
	if transaction.Action != "uninstall" ||
		!transaction.MaintenanceExisted ||
		!validLowerSHA256(transaction.PreviousMaintenanceSHA256) {
		return "", errors.New("uninstall transaction lacks an authenticated maintenance executable snapshot")
	}
	return transaction.PreviousMaintenanceSHA256, nil
}

func buildDeferredUninstallCleanupRecord(
	transaction setupTransaction,
	paths hookruntime.Paths,
	transactionRoot, command, bootIdentifier string,
) (deferredUninstallCleanupRecord, error) {
	for _, target := range []struct {
		path      string
		directory bool
	}{
		{path: paths.Root, directory: true},
		{path: paths.Launcher},
		{path: paths.State},
	} {
		var err error
		if target.directory {
			err = safefile.ValidatePrivateDirectory(target.path)
		} else {
			err = safefile.ValidatePrivateFile(target.path)
		}
		if err != nil {
			return deferredUninstallCleanupRecord{}, err
		}
	}
	state, recognized, err := hookruntime.ReadSetupPostureAt(paths, paths.Launcher)
	if err != nil || !recognized {
		return deferredUninstallCleanupRecord{}, errors.Join(
			errors.New("disabled stable HookRuntime was not recognized"),
			err,
		)
	}
	expectedHookPath := filepath.Join(transaction.InstallRoot, "bin", hookruntime.LauncherName)
	if state.Status != hookruntime.StatusDisabled ||
		state.TransactionID != transaction.ID ||
		state.SchemaVersion != hookruntime.SchemaVersion ||
		state.LauncherKind != hookruntime.LauncherKindTrampoline ||
		!samePath(state.HookPath, expectedHookPath) ||
		!validLowerSHA256(state.HookSHA256) {
		return deferredUninstallCleanupRecord{}, errors.New("disabled HookRuntime does not match the completed trampoline uninstall")
	}
	info, err := os.Lstat(paths.Launcher)
	if err != nil {
		return deferredUninstallCleanupRecord{}, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
		info.Size() <= 0 || info.Size() > hookruntime.MaxHookLauncherBytes {
		return deferredUninstallCleanupRecord{}, errors.New("stable HookRuntime launcher violates the accepted size or file-type contract")
	}
	machine, portable, err := portableExecutableMachine(paths.Launcher)
	if err != nil || !portable || machine != imageFileMachineAMD64 {
		return deferredUninstallCleanupRecord{}, errors.Join(
			errors.New("stable HookRuntime launcher is not a Windows x64 executable"),
			err,
		)
	}
	metadata, err := inspectEmbeddedAuthenticode(paths.Launcher)
	if err != nil {
		return deferredUninstallCleanupRecord{}, fmt.Errorf("inspect stable HookRuntime launcher Authenticode: %w", err)
	}
	unsignedLocal := !metadata.Present
	if transaction.PreviousState != nil &&
		transaction.PreviousState.UnsignedLocalArtifact != unsignedLocal {
		return deferredUninstallCleanupRecord{}, errors.New("stable HookRuntime launcher signing posture differs from installer state")
	}
	if metadata.Present {
		if !metadata.PublisherMatchesCisco || !metadata.RFC3161TimestampPresent || metadata.NestedSignaturePresent {
			return deferredUninstallCleanupRecord{}, errors.New("stable HookRuntime launcher lacks the required Cisco RFC3161 Authenticode identity")
		}
		if err := verifyEmbeddedAuthenticodeTrust(paths.Launcher); err != nil {
			return deferredUninstallCleanupRecord{}, fmt.Errorf("verify stable HookRuntime launcher Authenticode: %w", err)
		}
	}
	maintenanceDigest, err := fileSHA256(transaction.MaintenancePath)
	if err != nil {
		return deferredUninstallCleanupRecord{}, fmt.Errorf("hash deferred cleanup executable: %w", err)
	}
	expectedMaintenanceDigest, err := authenticatedUninstallMaintenanceDigest(transaction)
	if err != nil {
		return deferredUninstallCleanupRecord{}, err
	}
	if !strings.EqualFold(maintenanceDigest, expectedMaintenanceDigest) {
		return deferredUninstallCleanupRecord{}, errors.New("deferred cleanup executable differs from the uninstall transaction")
	}
	if err := verifySetupExecutablePolicyAt(transaction.MaintenancePath, unsignedLocal); err != nil {
		return deferredUninstallCleanupRecord{}, fmt.Errorf("verify deferred cleanup executable policy: %w", err)
	}
	connectors := append([]string(nil), transaction.PreviousConnectors...)
	slices.Sort(connectors)
	recordPath := deferredUninstallCleanupPath(transactionRoot)
	return deferredUninstallCleanupRecord{
		SchemaVersion:           deferredUninstallCleanupSchemaVersion,
		Status:                  deferredCleanupStatusPending,
		TransactionID:           transaction.ID,
		UninstallBootIdentifier: bootIdentifier,
		RuntimeRoot:             paths.Root,
		LauncherPath:            paths.Launcher,
		StatePath:               paths.State,
		RetiredLauncherPath:     retiredHookRuntimePath(paths.Launcher, transaction.ID),
		RetiredStatePath:        retiredHookRuntimePath(paths.State, transaction.ID),
		LauncherSHA256:          state.LauncherSHA256,
		LauncherSize:            info.Size(),
		LauncherKind:            state.LauncherKind,
		HookPath:                state.HookPath,
		HookSHA256:              state.HookSHA256,
		LauncherSigned:          metadata.Present,
		SignerThumbprintSHA256:  metadata.SignerThumbprintSHA256,
		UnsignedLocalArtifact:   unsignedLocal,
		MaintenancePath:         transaction.MaintenancePath,
		MaintenanceSHA256:       maintenanceDigest,
		InstallerStateRoot:      transactionRoot,
		JournalPath:             journalPaths(transactionRoot).Journal,
		RecordPath:              recordPath,
		CacheAckPath:            deferredUninstallCleanupAckPath(transaction.MaintenancePath),
		RunValueName:            deferredCleanupRunValueName,
		RunCommand:              command,
		VerifiedConnectors:      connectors,
	}, nil
}

func verifyRemovedConnectorsAfterUninstall(transaction setupTransaction) error {
	if len(transaction.PreviousConnectors) == 0 {
		return nil
	}
	maintenance, err := prepareConnectorMaintenanceGateway()
	if err != nil {
		return err
	}
	if maintenance.cleanup == nil {
		maintenance.cleanup = func() {}
	}
	defer maintenance.cleanup()
	for _, connectorName := range transaction.PreviousConnectors {
		for _, configHome := range connectorCleanupHomes(transaction, connectorName) {
			env := connectorLifecycleEnvForHome(transaction, connectorName, configHome)
			if err := runConnectorLifecycleWithEnv(
				maintenance.path,
				transaction.DataRoot,
				connectorName,
				"verify",
				env,
			); err != nil {
				return fmt.Errorf(
					"verify %s connector is empty at %s before deferred cleanup: %w",
					connectorName,
					configHome,
					err,
				)
			}
		}
	}
	return nil
}

func readDeferredUninstallCleanupRecord(path string) (*deferredUninstallCleanupRecord, error) {
	root := filepath.Dir(path)
	if _, err := os.Lstat(root); errors.Is(err, os.ErrNotExist) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	if err := validatePrivateTransactionPath(root, true); err != nil {
		return nil, err
	}
	if err := cleanupSetupJournalTemps(root, filepath.Base(path)+".new."); err != nil {
		return nil, err
	}
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	if err := validatePrivateTransactionPath(path, false); err != nil {
		return nil, err
	}
	var record deferredUninstallCleanupRecord
	if err := readJSON(path, &record); err != nil {
		return nil, fmt.Errorf("read deferred uninstall cleanup record: %w", err)
	}
	return &record, nil
}

func runDeferredUninstallCleanup(opts options) (int, error) {
	transactionRoot, err := defaultTransactionRoot()
	if err != nil {
		return retryRequiredCode, err
	}
	maintenancePath, err := defaultMaintenancePath()
	if err != nil {
		return retryRequiredCode, err
	}
	paths, err := hookruntime.CurrentUserPaths()
	if err != nil {
		return retryRequiredCode, err
	}
	recordPath := deferredUninstallCleanupPath(transactionRoot)
	record, err := readDeferredUninstallCleanupRecord(recordPath)
	if err != nil {
		return retryRequiredCode, err
	}
	if record == nil {
		ackPath := deferredUninstallCleanupAckPath(maintenancePath)
		ack, ackErr := readDeferredUninstallCleanupRecord(ackPath)
		if ackErr != nil {
			return retryRequiredCode, ackErr
		}
		if ack == nil {
			return retryRequiredCode, errors.New("deferred uninstall cleanup record is missing")
		}
		record = ack
	}
	command, err := deferredCleanupRunCommand(maintenancePath, record.TransactionID)
	if err != nil {
		return retryRequiredCode, err
	}
	if err := validateDeferredUninstallCleanupRecord(
		*record,
		paths,
		transactionRoot,
		maintenancePath,
		deferredCleanupRunValueName,
		command,
	); err != nil {
		return retryRequiredCode, err
	}
	if record.TransactionID != opts.CleanupTransaction {
		return retryRequiredCode, errors.New("deferred uninstall cleanup transaction does not match CLEANUPTRANSACTION")
	}
	if record.Status == deferredCleanupStatusSuperseded {
		if err := removeDeferredCleanupRunValue(record.RunCommand); err != nil {
			return retryRequiredCode, err
		}
		return 0, nil
	}

	currentBoot, err := queryDeferredCleanupBootIdentifier()
	if err != nil {
		return retryRequiredCode, err
	}
	if err := validateDeferredCleanupBootTransition(*record, currentBoot); err != nil {
		if !errors.Is(err, errUninstallCleanupRequiresRestart) {
			return retryRequiredCode, err
		}
		if !opts.Quiet {
			fmt.Println("DefenseClaw cleanup remains pending until Windows completes a genuine restart.")
		}
		return restartRequiredCode, nil
	}
	runtimePresent := false
	if _, err := os.Lstat(record.RuntimeRoot); err == nil {
		runtimePresent = true
	} else if !errors.Is(err, os.ErrNotExist) {
		return retryRequiredCode, err
	}

	var authorized *setupJournal
	if record.Status == deferredCleanupStatusPending ||
		(record.Status == deferredCleanupStatusRuntimeRetired && runtimePresent) {
		authorized, err = validateConvergedDeferredCleanup(*record, paths)
		if err != nil {
			return retryRequiredCode, err
		}
		if err := verifyDeferredCleanupConnectors(authorized.Transaction); err != nil {
			return retryRequiredCode, err
		}

		ctx, cancel := context.WithTimeout(context.Background(), setupExecutableReleaseTimeout)
		defer cancel()
		err = hookruntime.WithGatewayStartLock(ctx, func() error {
			lockedRecord, recordLock, err := readLockedCleanupRecord(record.RecordPath)
			if err != nil {
				return err
			}
			defer recordLock.Close()
			if !reflect.DeepEqual(*record, lockedRecord) {
				return errors.New("deferred uninstall cleanup record changed before HookRuntime retirement")
			}
			lockedJournal, journalLock, err := readLockedSetupJournal(record.JournalPath)
			if err != nil {
				return err
			}
			defer journalLock.Close()
			if lockedJournal.Phase != setupPhaseConverged ||
				!setupTransactionsEqual(lockedJournal.Transaction, authorized.Transaction) {
				return errors.New("converged uninstall journal changed before HookRuntime retirement")
			}
			if err := recordLock.Close(); err != nil {
				return err
			}
			return retireDisabledHookRuntime(record, currentBoot)
		})
		if err != nil {
			return retryRequiredCode, fmt.Errorf("retire disabled HookRuntime: %w", err)
		}
	}

	if err := finishDeferredInstallerStateCleanup(*record); err != nil {
		return retryRequiredCode, err
	}
	if !opts.Quiet {
		fmt.Println("DefenseClaw post-restart cleanup completed.")
	}
	return 0, nil
}

func validateDeferredCleanupBootTransition(
	record deferredUninstallCleanupRecord,
	currentBoot string,
) error {
	if !validBootIdentifier(currentBoot) {
		return errors.New("current Windows boot identifier is invalid")
	}
	if currentBoot == record.UninstallBootIdentifier {
		return errUninstallCleanupRequiresRestart
	}
	return nil
}

func validateConvergedDeferredCleanup(
	record deferredUninstallCleanupRecord,
	paths hookruntime.Paths,
) (*setupJournal, error) {
	journal, lock, err := readLockedSetupJournal(record.JournalPath)
	if err != nil {
		return nil, err
	}
	defer lock.Close()
	if err := validateConvergedDeferredCleanupJournal(record, paths, journal); err != nil {
		return nil, err
	}
	return &journal, nil
}

func validateConvergedDeferredCleanupJournal(
	record deferredUninstallCleanupRecord,
	paths hookruntime.Paths,
	journal setupJournal,
) error {
	if journal.SchemaVersion != setupJournalSchemaVersion ||
		journal.Phase != setupPhaseConverged ||
		journal.Transaction.Action != "uninstall" ||
		journal.Transaction.ID != record.TransactionID {
		return errors.New("deferred cleanup requires the exact converged uninstall journal")
	}
	expected, err := transactionExpectationsFromKnownFolders(
		journal.Transaction.InstallRoot,
		journal.Transaction.DataRoot,
	)
	if err != nil {
		return err
	}
	if err := validateSetupTransaction(journal.Transaction, expected); err != nil {
		return fmt.Errorf("validate converged uninstall transaction: %w", err)
	}
	journalMaintenanceDigest, err := authenticatedUninstallMaintenanceDigest(journal.Transaction)
	if err != nil {
		return err
	}
	if !samePath(journal.Transaction.MaintenancePath, record.MaintenancePath) ||
		!strings.EqualFold(journalMaintenanceDigest, record.MaintenanceSHA256) {
		return errors.New("converged uninstall journal does not match deferred cleanup maintenance identity")
	}
	expectedHookPath := filepath.Join(
		journal.Transaction.InstallRoot,
		"bin",
		hookruntime.LauncherName,
	)
	if !samePath(record.HookPath, expectedHookPath) {
		return errors.New("converged uninstall journal does not match deferred cleanup hook identity")
	}
	connectors := append([]string(nil), journal.Transaction.PreviousConnectors...)
	slices.Sort(connectors)
	if !slices.Equal(connectors, record.VerifiedConnectors) {
		return errors.New("converged uninstall connector set does not match deferred cleanup")
	}
	for _, path := range []string{
		journal.Transaction.InstallRoot,
		journal.Transaction.StagingPath,
		journal.Transaction.BackupPath,
		journal.Transaction.TrashPath,
		journal.Transaction.MaintenanceNew,
		journal.Transaction.MaintenanceBackup,
	} {
		if _, err := os.Lstat(path); err == nil {
			return fmt.Errorf("converged uninstall still retains transaction artifact: %s", path)
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	reconciliation, err := readConnectorReconciliation()
	if err != nil {
		return err
	}
	if reconciliation != nil {
		return errors.New("connector reconciliation state is not empty")
	}
	if err := validateDeferredCleanupMaintenance(record); err != nil {
		return err
	}
	if !samePath(record.RuntimeRoot, paths.Root) {
		return errors.New("converged uninstall cleanup names a non-canonical HookRuntime")
	}
	return nil
}

func validateDeferredCleanupMaintenance(record deferredUninstallCleanupRecord) error {
	self, err := os.Executable()
	if err != nil {
		return err
	}
	if !samePath(self, record.MaintenancePath) {
		return errors.New("deferred cleanup must run from the transaction-owned maintenance executable")
	}
	if err := validatePrivateTransactionPath(filepath.Dir(record.MaintenancePath), true); err != nil {
		return err
	}
	if err := validatePrivateTransactionPath(record.MaintenancePath, false); err != nil {
		return err
	}
	digest, err := fileSHA256(record.MaintenancePath)
	if err != nil {
		return err
	}
	if !strings.EqualFold(digest, record.MaintenanceSHA256) {
		return errors.New("deferred cleanup maintenance executable digest changed")
	}
	if err := verifySetupExecutablePolicyAt(record.MaintenancePath, record.UnsignedLocalArtifact); err != nil {
		return fmt.Errorf("verify deferred cleanup maintenance executable policy: %w", err)
	}
	return nil
}

func supersedeDeferredUninstallCleanup() error {
	transactionRoot, err := defaultTransactionRoot()
	if err != nil {
		return err
	}
	recordPath := deferredUninstallCleanupPath(transactionRoot)
	record, err := readDeferredUninstallCleanupRecord(recordPath)
	if err != nil {
		return err
	}
	if record == nil {
		maintenancePath, err := defaultMaintenancePath()
		if err != nil {
			return err
		}
		ackPath := deferredUninstallCleanupAckPath(maintenancePath)
		ack, err := readDeferredUninstallCleanupRecord(ackPath)
		if err != nil || ack == nil {
			return err
		}
		command, err := deferredCleanupRunCommand(maintenancePath, ack.TransactionID)
		if err != nil {
			return err
		}
		paths, err := hookruntime.CurrentUserPaths()
		if err != nil {
			return err
		}
		if err := validateDeferredUninstallCleanupRecord(
			*ack,
			paths,
			transactionRoot,
			maintenancePath,
			deferredCleanupRunValueName,
			command,
		); err != nil {
			return err
		}
		if ack.Status != deferredCleanupStatusRuntimeRetired {
			return errors.New("final cleanup acknowledgement is not terminal")
		}
		if err := removeDeferredCleanupRunValue(ack.RunCommand); err != nil {
			return err
		}
		return deletePrivatePathByHandle(ackPath, false)
	}
	paths, err := hookruntime.CurrentUserPaths()
	if err != nil {
		return err
	}
	command, err := deferredCleanupRunCommand(record.MaintenancePath, record.TransactionID)
	if err != nil {
		return err
	}
	if err := validateDeferredUninstallCleanupRecord(
		*record,
		paths,
		transactionRoot,
		record.MaintenancePath,
		deferredCleanupRunValueName,
		command,
	); err != nil {
		return err
	}
	return supersedeDeferredUninstallCleanupRecord(
		record,
		paths,
		deferredCleanupSupersessionOps{
			validateJournal: validateConvergedDeferredCleanupJournal,
			terminalize: func(transaction setupTransaction) error {
				return transitionSetupJournal(
					transaction,
					setupPhaseConverged,
					setupPhaseComplete,
				)
			},
			remove: func(record *deferredUninstallCleanupRecord) error {
				return removeSupersededDeferredCleanupRecord(
					record,
					removeDeferredCleanupRunValue,
				)
			},
		},
		nil,
		nil,
	)
}

type deferredCleanupSupersessionOps struct {
	validateJournal func(
		deferredUninstallCleanupRecord,
		hookruntime.Paths,
		setupJournal,
	) error
	terminalize func(setupTransaction) error
	remove      func(*deferredUninstallCleanupRecord) error
}

func supersedeDeferredUninstallCleanupRecord(
	record *deferredUninstallCleanupRecord,
	paths hookruntime.Paths,
	ops deferredCleanupSupersessionOps,
	afterSuperseded func() error,
	afterTerminal func() error,
) error {
	if record == nil {
		return errors.New("deferred uninstall cleanup record is unavailable")
	}
	if record.Status != deferredCleanupStatusPending &&
		record.Status != deferredCleanupStatusSuperseded {
		return errors.New("only a pending deferred cleanup can be superseded")
	}

	lockedRecord, recordLock, err := readLockedCleanupRecord(record.RecordPath)
	if err != nil {
		return err
	}
	defer recordLock.Close()
	if !reflect.DeepEqual(*record, lockedRecord) {
		return errors.New("deferred uninstall cleanup record changed before supersession")
	}

	document, journalLock, err := readLockedSetupJournalDocument(record.JournalPath)
	if err != nil {
		return err
	}
	defer journalLock.Close()

	if document.Terminal {
		if lockedRecord.Status != deferredCleanupStatusSuperseded {
			return errors.New("terminal setup journal lacks a durable superseded cleanup record")
		}
	} else {
		if document.Journal.SchemaVersion != setupJournalSchemaVersion ||
			document.Journal.Phase != setupPhaseConverged ||
			document.Journal.Transaction.Action != "uninstall" ||
			document.Journal.Transaction.ID != lockedRecord.TransactionID {
			return errors.New("refusing to supersede cleanup without the exact converged uninstall journal")
		}
		if ops.validateJournal == nil {
			return errors.New("deferred cleanup supersession journal validator is unavailable")
		}
		if err := ops.validateJournal(lockedRecord, paths, document.Journal); err != nil {
			return fmt.Errorf("refusing to supersede unauthenticated deferred cleanup: %w", err)
		}
	}
	if err := recordLock.Close(); err != nil {
		return err
	}
	if err := journalLock.Close(); err != nil {
		return err
	}

	if !document.Terminal {
		if err := markDeferredCleanupSuperseded(record); err != nil {
			return err
		}
		if afterSuperseded != nil {
			if err := afterSuperseded(); err != nil {
				return err
			}
		}
		if ops.terminalize == nil {
			return errors.New("deferred cleanup supersession terminalizer is unavailable")
		}
		if err := ops.terminalize(document.Journal.Transaction); err != nil {
			return fmt.Errorf("terminalize superseded uninstall transaction: %w", err)
		}
		if afterTerminal != nil {
			if err := afterTerminal(); err != nil {
				return err
			}
		}
	}
	if ops.remove == nil {
		return errors.New("deferred cleanup supersession remover is unavailable")
	}
	return ops.remove(record)
}

func markDeferredCleanupSuperseded(record *deferredUninstallCleanupRecord) error {
	if record == nil {
		return errors.New("deferred uninstall cleanup record is unavailable")
	}
	if record.Status == deferredCleanupStatusSuperseded {
		return nil
	}
	if record.Status != deferredCleanupStatusPending {
		return errors.New("only a pending deferred cleanup can be marked superseded")
	}
	record.Status = deferredCleanupStatusSuperseded
	record.CleanupBootIdentifier = ""
	if err := writeDurableValue(record.RecordPath, *record, true); err != nil {
		return fmt.Errorf("durably supersede deferred uninstall cleanup: %w", err)
	}
	return nil
}

func removeSupersededDeferredCleanupRecord(
	record *deferredUninstallCleanupRecord,
	removeRun func(string) error,
) error {
	if record == nil {
		return errors.New("deferred uninstall cleanup record is unavailable")
	}
	if record.Status != deferredCleanupStatusSuperseded {
		return errors.New("refusing to remove a cleanup record before durable supersession")
	}
	if err := removeRun(record.RunCommand); err != nil {
		return err
	}
	if err := deletePrivatePathByHandle(record.RecordPath, false); err != nil &&
		!errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := deletePrivatePathByHandle(record.CacheAckPath, false); err != nil &&
		!errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

type lockedCleanupPath struct {
	file            *os.File
	path            string
	info            os.FileInfo
	byteRangeLocked bool
}

func (locked *lockedCleanupPath) Close() error {
	if locked == nil || locked.file == nil {
		return nil
	}
	if locked.byteRangeLocked {
		var overlapped windows.Overlapped
		_ = windows.UnlockFileEx(
			windows.Handle(locked.file.Fd()),
			0,
			math.MaxUint32,
			math.MaxUint32,
			&overlapped,
		)
		locked.byteRangeLocked = false
	}
	err := locked.file.Close()
	locked.file = nil
	return err
}

func openLockedCleanupPath(path string, directory bool) (*lockedCleanupPath, error) {
	return openLockedCleanupPathWithDelete(path, directory, !directory)
}

func openLockedCleanupPathWithDelete(
	path string,
	directory bool,
	deleteAccess bool,
) (*lockedCleanupPath, error) {
	if err := winpath.RejectReparseChain(path); err != nil {
		return nil, err
	}
	encoded, err := winpath.UTF16Ptr(path)
	if err != nil {
		return nil, err
	}
	access := uint32(windows.GENERIC_READ | windows.READ_CONTROL | windows.DELETE)
	flags := uint32(windows.FILE_ATTRIBUTE_NORMAL | windows.FILE_FLAG_OPEN_REPARSE_POINT)
	// Windows rename/disposition operations require compatible sharing on the
	// source and parent handles.
	share := uint32(windows.FILE_SHARE_READ | windows.FILE_SHARE_WRITE | windows.FILE_SHARE_DELETE)
	if directory {
		access = windows.FILE_LIST_DIRECTORY | windows.FILE_READ_ATTRIBUTES | windows.READ_CONTROL
		if deleteAccess {
			access |= windows.DELETE
		}
		flags = windows.FILE_FLAG_BACKUP_SEMANTICS | windows.FILE_FLAG_OPEN_REPARSE_POINT
		// Windows performs child rename/disposition work through the parent
		// directory. Share that access while retaining this identity handle.
		share |= windows.FILE_SHARE_WRITE
	}
	handle, err := windows.CreateFile(
		encoded,
		access,
		share,
		nil,
		windows.OPEN_EXISTING,
		flags,
		0,
	)
	if err != nil {
		return nil, &os.PathError{Op: "lock", Path: path, Err: err}
	}
	file := os.NewFile(uintptr(handle), path)
	if file == nil {
		_ = windows.CloseHandle(handle)
		return nil, errors.New("wrap deferred cleanup path handle")
	}
	fail := func(cause error) (*lockedCleanupPath, error) {
		_ = file.Close()
		return nil, cause
	}
	byteRangeLocked := false
	if !directory {
		var overlapped windows.Overlapped
		if err := windows.LockFileEx(
			handle,
			windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY,
			0,
			math.MaxUint32,
			math.MaxUint32,
			&overlapped,
		); err != nil {
			return fail(fmt.Errorf("lock deferred cleanup file contents: %w", err))
		}
		byteRangeLocked = true
	}
	var byHandle windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &byHandle); err != nil {
		return fail(err)
	}
	isDirectory := byHandle.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0
	if byHandle.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 ||
		isDirectory != directory {
		return fail(fmt.Errorf("deferred cleanup path has an unexpected handle type: %s", path))
	}
	finalPath, err := cleanupFinalPathForHandle(handle)
	if err != nil {
		return fail(err)
	}
	if !samePath(finalPath, path) {
		return fail(fmt.Errorf("deferred cleanup path final identity changed: got %s, want %s", finalPath, path))
	}
	if err := safefile.ValidatePrivateHandle(handle); err != nil {
		return fail(err)
	}
	info, err := file.Stat()
	if err != nil {
		return fail(err)
	}
	return &lockedCleanupPath{
		file:            file,
		path:            path,
		info:            info,
		byteRangeLocked: byteRangeLocked,
	}, nil
}

func validateSameLockedCleanupIdentity(first, second *lockedCleanupPath) error {
	if first == nil || first.file == nil || second == nil || second.file == nil {
		return errors.New("deferred cleanup identity handle is unavailable")
	}
	var firstInfo windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(
		windows.Handle(first.file.Fd()),
		&firstInfo,
	); err != nil {
		return err
	}
	var secondInfo windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(
		windows.Handle(second.file.Fd()),
		&secondInfo,
	); err != nil {
		return err
	}
	if firstInfo.VolumeSerialNumber != secondInfo.VolumeSerialNumber ||
		firstInfo.FileIndexHigh != secondInfo.FileIndexHigh ||
		firstInfo.FileIndexLow != secondInfo.FileIndexLow {
		return errors.New("deferred cleanup object identity changed")
	}
	return nil
}

func cleanupFinalPathForHandle(handle windows.Handle) (string, error) {
	buffer := make([]uint16, 512)
	for {
		length, err := windows.GetFinalPathNameByHandle(handle, &buffer[0], uint32(len(buffer)), 0)
		if err != nil {
			return "", err
		}
		if length < uint32(len(buffer)) {
			value := windows.UTF16ToString(buffer[:length])
			switch {
			case strings.HasPrefix(value, `\\?\UNC\`):
				value = `\\` + strings.TrimPrefix(value, `\\?\UNC\`)
			case strings.HasPrefix(value, `\\?\`):
				value = strings.TrimPrefix(value, `\\?\`)
			}
			return value, nil
		}
		if length == 0 {
			return "", errors.New("deferred cleanup handle final path is empty")
		}
		buffer = make([]uint16, length+1)
	}
}

func readLockedJSON(path string, limit int64, target any) (*lockedCleanupPath, error) {
	locked, err := openLockedCleanupPath(path, false)
	if err != nil {
		return nil, err
	}
	fail := func(cause error) (*lockedCleanupPath, error) {
		_ = locked.Close()
		return nil, cause
	}
	if locked.info.Size() < 0 || locked.info.Size() > limit {
		return fail(fmt.Errorf("deferred cleanup JSON exceeds the %d-byte limit: %s", limit, path))
	}
	body, err := io.ReadAll(io.LimitReader(locked.file, limit+1))
	if err != nil {
		return fail(err)
	}
	if int64(len(body)) > limit {
		return fail(fmt.Errorf("deferred cleanup JSON exceeds the %d-byte limit: %s", limit, path))
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return fail(err)
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return fail(errors.New("deferred cleanup JSON contains trailing data"))
	}
	if _, err := locked.file.Seek(0, io.SeekStart); err != nil {
		return fail(err)
	}
	return locked, nil
}

func readLockedCleanupRecord(path string) (
	deferredUninstallCleanupRecord,
	*lockedCleanupPath,
	error,
) {
	var record deferredUninstallCleanupRecord
	locked, err := readLockedJSON(path, deferredCleanupFileLimit, &record)
	return record, locked, err
}

func readLockedSetupJournal(path string) (setupJournal, *lockedCleanupPath, error) {
	document, locked, err := readLockedSetupJournalDocument(path)
	if err != nil {
		return setupJournal{}, nil, err
	}
	return document.Journal, locked, nil
}

func readLockedSetupJournalDocument(
	path string,
) (setupJournalDocument, *lockedCleanupPath, error) {
	locked, err := openLockedCleanupPath(path, false)
	if err != nil {
		return setupJournalDocument{}, nil, err
	}
	fail := func(cause error) (setupJournalDocument, *lockedCleanupPath, error) {
		_ = locked.Close()
		return setupJournalDocument{}, nil, cause
	}
	if locked.info.Size() < 0 || locked.info.Size() > deferredCleanupFileLimit {
		return fail(fmt.Errorf(
			"locked setup journal exceeds the %d-byte limit",
			deferredCleanupFileLimit,
		))
	}
	body, err := io.ReadAll(io.LimitReader(locked.file, deferredCleanupFileLimit+1))
	if err != nil {
		return fail(err)
	}
	if int64(len(body)) > deferredCleanupFileLimit {
		return fail(fmt.Errorf(
			"locked setup journal exceeds the %d-byte limit",
			deferredCleanupFileLimit,
		))
	}
	if _, err := locked.file.Seek(0, io.SeekStart); err != nil {
		return fail(err)
	}

	var terminal terminalSetupJournal
	if err := decodeSetupJournalJSON(body, &terminal); err == nil &&
		terminal == frozenTerminalSetupJournal() {
		return setupJournalDocument{
			Journal: setupJournal{
				SchemaVersion: terminal.SchemaVersion,
				Phase:         terminal.Phase,
			},
			Terminal: true,
		}, locked, nil
	}
	var journal setupJournal
	if err := decodeSetupJournalJSON(body, &journal); err != nil {
		return fail(err)
	}
	if journal.SchemaVersion != setupJournalLegacySchemaVersion &&
		journal.SchemaVersion != setupJournalSchemaVersion {
		return fail(errors.New("locked setup journal has an unsupported schema"))
	}
	switch journal.Phase {
	case setupPhaseIntent, setupPhaseQuiescing, setupPhasePublished,
		setupPhaseCommitted, setupPhaseConverged, setupPhaseComplete:
	default:
		return fail(errors.New("locked setup journal has an unsupported phase"))
	}
	return setupJournalDocument{Journal: journal}, locked, nil
}

func hashLockedCleanupFile(locked *lockedCleanupPath) (string, error) {
	if locked == nil || locked.file == nil {
		return "", errors.New("deferred cleanup file handle is unavailable")
	}
	if _, err := locked.file.Seek(0, io.SeekStart); err != nil {
		return "", err
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, locked.file); err != nil {
		return "", err
	}
	if _, err := locked.file.Seek(0, io.SeekStart); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

type cleanupFileRenameInformation struct {
	ReplaceIfExists uint32
	RootDirectory   windows.Handle
	FileNameLength  uint32
	FileName        [1]uint16
}

func renameLockedCleanupPath(
	locked *lockedCleanupPath,
	parent *lockedCleanupPath,
	destination string,
) error {
	if locked == nil || locked.file == nil || parent == nil || parent.file == nil {
		return errors.New("deferred cleanup rename handle is unavailable")
	}
	if !samePath(filepath.Dir(locked.path), filepath.Dir(destination)) {
		return errors.New("deferred cleanup rename must remain within the authenticated directory")
	}
	parentPath, err := cleanupFinalPathForHandle(windows.Handle(parent.file.Fd()))
	if err != nil {
		return err
	}
	if !samePath(parentPath, filepath.Dir(destination)) {
		return errors.New("deferred cleanup rename parent identity changed")
	}
	if _, err := os.Lstat(destination); err == nil {
		return fmt.Errorf("deferred cleanup rename destination already exists: %s", destination)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := winpath.RejectReparseChain(filepath.Dir(destination)); err != nil {
		return err
	}
	finalPath, err := cleanupFinalPathForHandle(windows.Handle(locked.file.Fd()))
	if err != nil {
		return err
	}
	if !samePath(finalPath, locked.path) {
		return fmt.Errorf(
			"deferred cleanup target identity changed before rename: got %q, want %q",
			finalPath,
			locked.path,
		)
	}
	encoded, err := windows.UTF16FromString(filepath.Base(destination))
	if err != nil {
		return err
	}
	encoded = encoded[:len(encoded)-1]
	var header cleanupFileRenameInformation
	headerSize := int(unsafe.Offsetof(header.FileName))
	buffer := make([]byte, headerSize+len(encoded)*2)
	info := (*cleanupFileRenameInformation)(unsafe.Pointer(&buffer[0]))
	info.RootDirectory = windows.Handle(parent.file.Fd())
	info.FileNameLength = uint32(len(encoded) * 2)
	copy(unsafe.Slice((*uint16)(unsafe.Pointer(&buffer[headerSize])), len(encoded)), encoded)
	var status windows.IO_STATUS_BLOCK
	if err := windows.NtSetInformationFile(
		windows.Handle(locked.file.Fd()),
		&status,
		&buffer[0],
		uint32(len(buffer)),
		windows.FileRenameInformation,
	); err != nil {
		return fmt.Errorf("rename exact deferred cleanup handle: %w", err)
	}
	finalPath, err = cleanupFinalPathForHandle(windows.Handle(locked.file.Fd()))
	if err != nil {
		return err
	}
	if !samePath(finalPath, destination) {
		return fmt.Errorf("renamed deferred cleanup handle resolved to %s, want %s", finalPath, destination)
	}
	locked.path = destination
	return nil
}

func deleteLockedCleanupPath(locked *lockedCleanupPath) error {
	if locked == nil || locked.file == nil {
		return errors.New("deferred cleanup delete handle is unavailable")
	}
	finalPath, err := cleanupFinalPathForHandle(windows.Handle(locked.file.Fd()))
	if err != nil {
		return err
	}
	if !samePath(finalPath, locked.path) {
		return fmt.Errorf(
			"deferred cleanup target identity changed before delete: got %q, want %q",
			finalPath,
			locked.path,
		)
	}
	disposition := byte(1)
	if err := windows.SetFileInformationByHandle(
		windows.Handle(locked.file.Fd()),
		windows.FileDispositionInfo,
		&disposition,
		1,
	); err != nil {
		return fmt.Errorf("delete exact deferred cleanup handle: %w", err)
	}
	return locked.Close()
}

func deletePrivatePathByHandle(path string, directory bool) error {
	locked, err := openLockedCleanupPathWithDelete(path, directory, true)
	if err != nil {
		return err
	}
	defer locked.Close()
	return deleteLockedCleanupPath(locked)
}

func readLockedCleanupDirectory(locked *lockedCleanupPath) ([]os.DirEntry, error) {
	if locked == nil || locked.file == nil {
		return nil, errors.New("deferred cleanup directory handle is unavailable")
	}
	encoded, err := winpath.UTF16Ptr(locked.path)
	if err != nil {
		return nil, err
	}
	handle, err := windows.CreateFile(
		encoded,
		windows.FILE_LIST_DIRECTORY|windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		return nil, &os.PathError{Op: "enumerate", Path: locked.path, Err: err}
	}
	file := os.NewFile(uintptr(handle), locked.path)
	if file == nil {
		_ = windows.CloseHandle(handle)
		return nil, errors.New("wrap deferred cleanup directory enumeration handle")
	}
	defer file.Close()

	var lockedInfo windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(windows.Handle(locked.file.Fd()), &lockedInfo); err != nil {
		return nil, err
	}
	var enumerationInfo windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &enumerationInfo); err != nil {
		return nil, err
	}
	if enumerationInfo.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 ||
		enumerationInfo.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 ||
		enumerationInfo.VolumeSerialNumber != lockedInfo.VolumeSerialNumber ||
		enumerationInfo.FileIndexHigh != lockedInfo.FileIndexHigh ||
		enumerationInfo.FileIndexLow != lockedInfo.FileIndexLow {
		return nil, errors.New("deferred cleanup directory identity changed before enumeration")
	}
	finalPath, err := cleanupFinalPathForHandle(handle)
	if err != nil {
		return nil, err
	}
	if !samePath(finalPath, locked.path) {
		return nil, fmt.Errorf(
			"deferred cleanup directory identity changed before enumeration: got %q, want %q",
			finalPath,
			locked.path,
		)
	}
	return file.ReadDir(-1)
}

func runtimeCleanupCandidate(canonical, retired string) (string, bool, error) {
	canonicalExists := pathExists(canonical)
	retiredExists := pathExists(retired)
	if canonicalExists && retiredExists {
		return "", false, errors.New("both canonical and retired HookRuntime paths exist")
	}
	if canonicalExists {
		return canonical, true, nil
	}
	if retiredExists {
		return retired, false, nil
	}
	return "", false, os.ErrNotExist
}

func retireDisabledHookRuntime(
	record *deferredUninstallCleanupRecord,
	cleanupBootIdentifier string,
) error {
	return retireDisabledHookRuntimeWithAfterAck(record, cleanupBootIdentifier, nil)
}

func retireDisabledHookRuntimeWithAfterAck(
	record *deferredUninstallCleanupRecord,
	cleanupBootIdentifier string,
	afterAck func() error,
) error {
	if record == nil {
		return errors.New("deferred cleanup record is unavailable")
	}
	resuming := record.Status == deferredCleanupStatusRuntimeRetired
	if record.Status != deferredCleanupStatusPending && !resuming {
		return errors.New("HookRuntime retirement requires a pending or acknowledged cleanup record")
	}
	if resuming && record.CleanupBootIdentifier != cleanupBootIdentifier {
		return errors.New("HookRuntime retirement acknowledgement belongs to a different boot")
	}
	root, err := openLockedCleanupPath(record.RuntimeRoot, true)
	if err != nil {
		return err
	}
	defer root.Close()
	entries, err := readLockedCleanupDirectory(root)
	if err != nil {
		return err
	}
	allowed := map[string]bool{
		filepath.Base(record.LauncherPath):        true,
		filepath.Base(record.StatePath):           true,
		filepath.Base(record.RetiredLauncherPath): true,
		filepath.Base(record.RetiredStatePath):    true,
	}
	for _, entry := range entries {
		if !allowed[entry.Name()] {
			return fmt.Errorf("unexpected HookRuntime cleanup entry: %s", entry.Name())
		}
	}
	launcherPath, renameLauncher, err := runtimeCleanupCandidate(
		record.LauncherPath,
		record.RetiredLauncherPath,
	)
	if err != nil {
		if !resuming || !errors.Is(err, os.ErrNotExist) {
			return errors.New("authenticated HookRuntime launcher is missing")
		}
		launcherPath = ""
	}
	statePath, renameState, err := runtimeCleanupCandidate(record.StatePath, record.RetiredStatePath)
	if err != nil {
		if !resuming || !errors.Is(err, os.ErrNotExist) {
			return errors.New("authenticated HookRuntime state is missing")
		}
		statePath = ""
	}
	if resuming && (renameLauncher || renameState) {
		return errors.New("acknowledged HookRuntime retirement contains a canonical live path")
	}
	if launcherPath != "" && record.LauncherSigned {
		if err := verifyEmbeddedAuthenticodeTrust(launcherPath); err != nil {
			return fmt.Errorf("verify HookRuntime launcher Authenticode before handle lock: %w", err)
		}
	}
	var launcher *lockedCleanupPath
	if launcherPath != "" {
		launcher, err = openLockedCleanupPath(launcherPath, false)
		if err != nil {
			return err
		}
		defer launcher.Close()
	}
	var stateFile *lockedCleanupPath
	if statePath != "" {
		stateFile, err = openLockedCleanupPath(statePath, false)
		if err != nil {
			return err
		}
		defer stateFile.Close()
	}

	if launcher != nil {
		if launcher.info.Size() != record.LauncherSize ||
			launcher.info.Size() <= 0 ||
			launcher.info.Size() > hookruntime.MaxHookLauncherBytes {
			return errors.New("HookRuntime launcher size changed before cleanup")
		}
		launcherDigest, err := hashLockedCleanupFile(launcher)
		if err != nil {
			return err
		}
		if !strings.EqualFold(launcherDigest, record.LauncherSHA256) {
			return errors.New("HookRuntime launcher digest changed before cleanup")
		}
		machine, portable, err := portableExecutableMachineFromReader(launcher.file)
		if err != nil || !portable || machine != imageFileMachineAMD64 {
			return errors.Join(errors.New("HookRuntime launcher architecture changed before cleanup"), err)
		}
		metadata, err := inspectEmbeddedAuthenticodeFromFile(launcher.file)
		if err != nil {
			return err
		}
		if metadata.Present != record.LauncherSigned ||
			metadata.SignerThumbprintSHA256 != record.SignerThumbprintSHA256 {
			return errors.New("HookRuntime launcher signer changed before cleanup")
		}
		if record.LauncherSigned {
			if !metadata.PublisherMatchesCisco || !metadata.RFC3161TimestampPresent ||
				metadata.NestedSignaturePresent {
				return errors.New("HookRuntime launcher no longer satisfies the Cisco Authenticode policy")
			}
		}
	}

	if stateFile != nil {
		var state hookruntime.State
		if _, err := stateFile.file.Seek(0, io.SeekStart); err != nil {
			return err
		}
		decoder := json.NewDecoder(io.LimitReader(stateFile.file, deferredCleanupFileLimit))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&state); err != nil {
			return fmt.Errorf("parse locked HookRuntime state: %w", err)
		}
		paths := hookruntime.Paths{
			Root:     record.RuntimeRoot,
			Launcher: record.LauncherPath,
			State:    record.StatePath,
		}
		if err := state.Validate(paths); err != nil {
			return err
		}
		if state.Status != hookruntime.StatusDisabled ||
			state.TransactionID != record.TransactionID ||
			state.LauncherKind != record.LauncherKind ||
			!samePath(state.HookPath, record.HookPath) ||
			!strings.EqualFold(state.HookSHA256, record.HookSHA256) ||
			!strings.EqualFold(state.LauncherSHA256, record.LauncherSHA256) {
			return errors.New("locked HookRuntime state does not match the deferred cleanup transaction")
		}
	}

	if renameLauncher && launcher != nil {
		if err := renameLockedCleanupPath(launcher, root, record.RetiredLauncherPath); err != nil {
			return err
		}
	}
	if renameState && stateFile != nil {
		if err := renameLockedCleanupPath(stateFile, root, record.RetiredStatePath); err != nil {
			return err
		}
	}

	if !resuming {
		next := *record
		next.Status = deferredCleanupStatusRuntimeRetired
		next.CleanupBootIdentifier = cleanupBootIdentifier
		if err := writeDurableValue(record.RecordPath, next, true); err != nil {
			return fmt.Errorf("persist HookRuntime retirement acknowledgement: %w", err)
		}
		*record = next
	}
	if afterAck != nil {
		if err := afterAck(); err != nil {
			return err
		}
	}
	if stateFile != nil {
		if err := deleteLockedCleanupPath(stateFile); err != nil {
			return err
		}
	}
	if launcher != nil {
		if err := deleteLockedCleanupPath(launcher); err != nil {
			return err
		}
	}
	if remaining, err := readLockedCleanupDirectory(root); err != nil {
		return err
	} else if len(remaining) != 0 {
		return errors.New("HookRuntime directory is not empty after exact file retirement")
	}
	deleteRoot, err := openLockedCleanupPathWithDelete(record.RuntimeRoot, true, true)
	if err != nil {
		return err
	}
	defer deleteRoot.Close()
	if err := validateSameLockedCleanupIdentity(root, deleteRoot); err != nil {
		return err
	}
	return deleteLockedCleanupPath(deleteRoot)
}

func finishDeferredInstallerStateCleanup(record deferredUninstallCleanupRecord) error {
	return finishDeferredInstallerStateCleanupWith(
		record,
		validateDeferredCleanupMaintenance,
		startDeferredCleanupFinalizer,
	)
}

func finishDeferredInstallerStateCleanupWith(
	record deferredUninstallCleanupRecord,
	validateMaintenance func(deferredUninstallCleanupRecord) error,
	startFinalizer func(deferredUninstallCleanupRecord, int) error,
) error {
	if record.Status != deferredCleanupStatusRuntimeRetired {
		return errors.New("installer-state cleanup requires a durable HookRuntime retirement acknowledgement")
	}
	for _, path := range []string{
		record.RuntimeRoot,
		record.LauncherPath,
		record.StatePath,
		record.RetiredLauncherPath,
		record.RetiredStatePath,
	} {
		if _, err := os.Lstat(path); err == nil {
			return fmt.Errorf("HookRuntime cleanup acknowledgement conflicts with retained path: %s", path)
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	if err := validateMaintenance(record); err != nil {
		return err
	}
	if current, err := readDeferredUninstallCleanupRecord(record.CacheAckPath); err != nil {
		return err
	} else if current == nil {
		if err := writeDurableValue(record.CacheAckPath, record, false); err != nil {
			return fmt.Errorf("persist final cleanup acknowledgement: %w", err)
		}
	} else if !reflect.DeepEqual(*current, record) {
		return errors.New("final cleanup acknowledgement differs from the retired transaction")
	}

	if _, err := os.Lstat(record.InstallerStateRoot); errors.Is(err, os.ErrNotExist) {
		if err := startFinalizer(record, os.Getpid()); err != nil {
			return fmt.Errorf("resume final uninstall cache cleanup: %w", err)
		}
		return nil
	} else if err != nil {
		return err
	}
	stateRoot, err := openLockedCleanupPath(record.InstallerStateRoot, true)
	if err != nil {
		return err
	}
	defer stateRoot.Close()
	entries, err := readLockedCleanupDirectory(stateRoot)
	if err != nil {
		return err
	}
	allowed := map[string]bool{
		filepath.Base(record.JournalPath): true,
		filepath.Base(record.RecordPath):  true,
		"setup.log":                       true,
	}
	for _, entry := range entries {
		if !allowed[entry.Name()] {
			return fmt.Errorf("unexpected installer-state cleanup entry: %s", entry.Name())
		}
	}
	if _, err := os.Lstat(record.JournalPath); err == nil {
		journal, lock, err := readLockedSetupJournal(record.JournalPath)
		if err != nil {
			return err
		}
		if journal.Phase != setupPhaseConverged ||
			journal.Transaction.Action != "uninstall" ||
			journal.Transaction.ID != record.TransactionID {
			_ = lock.Close()
			return errors.New("installer-state retirement found a non-converged uninstall journal")
		}
		if err := deleteLockedCleanupPath(lock); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	setupLog := filepath.Join(record.InstallerStateRoot, "setup.log")
	if err := deletePrivatePathByHandle(setupLog, false); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := deletePrivatePathByHandle(record.RecordPath, false); err != nil &&
		!errors.Is(err, os.ErrNotExist) {
		return err
	}
	if remaining, err := readLockedCleanupDirectory(stateRoot); err != nil {
		return err
	} else if len(remaining) != 0 {
		return errors.New("installer-state directory is not empty after exact marker retirement")
	}
	deleteStateRoot, err := openLockedCleanupPathWithDelete(
		record.InstallerStateRoot,
		true,
		true,
	)
	if err != nil {
		return err
	}
	defer deleteStateRoot.Close()
	if err := validateSameLockedCleanupIdentity(stateRoot, deleteStateRoot); err != nil {
		return err
	}
	if err := deleteLockedCleanupPath(deleteStateRoot); err != nil {
		return err
	}
	if err := startFinalizer(record, os.Getpid()); err != nil {
		return fmt.Errorf("start final uninstall cache cleanup: %w", err)
	}
	return nil
}

const deferredCleanupFinalizerWaitTimeout = 2 * time.Minute

func startDeferredCleanupFinalizerProcess(
	record deferredUninstallCleanupRecord,
	parentPID int,
) error {
	powerShell, err := systemPowerShellPath()
	if err != nil {
		return err
	}
	cmd := deferredCleanupFinalizerCommand(
		powerShell,
		record,
		parentPID,
		deferredCleanupFinalizerWaitTimeout,
	)
	if err := cmd.Start(); err != nil {
		return err
	}
	return cmd.Process.Release()
}

func deferredCleanupFinalizerCommand(
	powerShell string,
	record deferredUninstallCleanupRecord,
	parentPID int,
	waitTimeout time.Duration,
) *exec.Cmd {
	const script = `
$ackPath=$env:DEFENSECLAW_CLEANUP_ACK
$expectedID=$env:DEFENSECLAW_CLEANUP_TRANSACTION_ID
$parent=[int]$env:DEFENSECLAW_CLEANUP_PARENT_PID
$waitMilliseconds=[int]$env:DEFENSECLAW_CLEANUP_WAIT_MS

$parentExited=$false
$parentProcess=$null
try {
    $parentProcess=[Diagnostics.Process]::GetProcessById($parent)
    $parentExited=$parentProcess.WaitForExit($waitMilliseconds)
} catch {
    $parentExited=$_.Exception -is [ArgumentException] -or
        $_.Exception.InnerException -is [ArgumentException]
} finally {
    if ($null -ne $parentProcess) { $parentProcess.Dispose() }
}
if (-not $parentExited) { exit 0 }

$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
$mutex=$null
$ownsMutex=$false
try {
    $mutex=[Threading.Mutex]::new($false, 'Global\Cisco.DefenseClaw.Setup.'+$identity.User.Value)
    try {
        $ownsMutex=$mutex.WaitOne($waitMilliseconds)
    } catch [Threading.AbandonedMutexException] {
        $ownsMutex=$true
    }
    if (-not $ownsMutex) { exit 0 }

    $ackLock=[IO.File]::Open(
        $ackPath,
        [IO.FileMode]::Open,
        [IO.FileAccess]::Read,
        [IO.FileShare]::Read
    )
    try {
        $reader=[IO.StreamReader]::new($ackLock, [Text.Encoding]::UTF8, $true, 4096, $true)
        try {
            $record=($reader.ReadToEnd() | ConvertFrom-Json)
        } finally {
            $reader.Dispose()
        }
        if ($null -eq $record -or
            [int]$record.schema_version -ne 1 -or
            [string]$record.status -cne 'runtime-retired' -or
            [string]$record.transaction_id -cne $expectedID -or
            [string]$record.cleanup_boot_identifier -ceq [string]$record.uninstall_boot_identifier) {
            exit 0
        }

        $local=[Environment]::GetFolderPath([Environment+SpecialFolder]::LocalApplicationData)
        $expectedCache=[IO.Path]::GetFullPath([IO.Path]::Combine($local,'DefenseClaw','InstallerCache'))
        $expectedSetup=[IO.Path]::GetFullPath([IO.Path]::Combine($expectedCache,'DefenseClawSetup-x64.exe'))
        $expectedAck=[IO.Path]::GetFullPath([IO.Path]::Combine($expectedCache,'uninstall-cleanup-ack.json'))
        $expectedRunName='DefenseClawDeferredUninstallCleanup'
        $expectedRunCommand='"%LOCALAPPDATA%\DefenseClaw\InstallerCache\DefenseClawSetup-x64.exe" /cleanup /quiet CLEANUPTRANSACTION='+$expectedID
        $stateRoot=[IO.Path]::GetFullPath([IO.Path]::Combine($local,'DefenseClaw','InstallerState'))
        $runtimeRoot=[IO.Path]::GetFullPath([IO.Path]::Combine($local,'DefenseClaw','HookRuntime'))
        if (-not [string]::Equals([IO.Path]::GetFullPath([string]$record.maintenance_path),$expectedSetup,[StringComparison]::OrdinalIgnoreCase) -or
            -not [string]::Equals([IO.Path]::GetFullPath([string]$record.cache_ack_path),$expectedAck,[StringComparison]::OrdinalIgnoreCase) -or
            -not [string]::Equals([IO.Path]::GetFullPath([string]$record.runtime_root),$runtimeRoot,[StringComparison]::OrdinalIgnoreCase) -or
            [string]$record.run_value_name -cne $expectedRunName -or
            [string]$record.run_command -cne $expectedRunCommand -or
            [IO.Directory]::Exists($stateRoot) -or
            [IO.Directory]::Exists($runtimeRoot)) {
            exit 0
        }
        $cacheAttributes=[IO.File]::GetAttributes($expectedCache)
        if (($cacheAttributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
            ($cacheAttributes -band [IO.FileAttributes]::Directory) -eq 0) {
            exit 0
        }
        $entries=@([IO.Directory]::EnumerateFileSystemEntries($expectedCache))
        if ($entries.Count -ne 2 -or
            -not ($entries | Where-Object { [string]::Equals($_,$expectedSetup,[StringComparison]::OrdinalIgnoreCase) }) -or
            -not ($entries | Where-Object { [string]::Equals($_,$expectedAck,[StringComparison]::OrdinalIgnoreCase) })) {
            exit 0
        }
        foreach ($path in @($expectedSetup,$expectedAck)) {
            $attributes=[IO.File]::GetAttributes($path)
            if (($attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
                ($attributes -band [IO.FileAttributes]::Directory) -ne 0) {
                exit 0
            }
        }
        $setupLock=[IO.File]::Open(
            $expectedSetup,
            [IO.FileMode]::Open,
            [IO.FileAccess]::Read,
            [IO.FileShare]::Read
        )
        try {
            $sha=[Security.Cryptography.SHA256]::Create()
            try {
                $digest=([BitConverter]::ToString($sha.ComputeHash($setupLock))).Replace('-','').ToLowerInvariant()
            } finally {
                $sha.Dispose()
            }
            if ($digest -cne [string]$record.maintenance_sha256) { exit 0 }
        } finally {
            $setupLock.Dispose()
        }

        $run=[Microsoft.Win32.Registry]::CurrentUser.OpenSubKey(
            'Software\Microsoft\Windows\CurrentVersion\Run',
            $true
        )
        if ($null -ne $run) {
            try {
                $current=$run.GetValue(
                    [string]$record.run_value_name,
                    $null,
                    [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames
                )
                if ($null -ne $current -and [string]$current -cne [string]$record.run_command) {
                    exit 0
                }
                if ($null -ne $current) {
                    if ($run.GetValueKind([string]$record.run_value_name) -ne
                        [Microsoft.Win32.RegistryValueKind]::ExpandString) {
                        exit 0
                    }
                    $run.DeleteValue([string]$record.run_value_name,$false)
                }
            } finally {
                $run.Dispose()
            }
        }
    } finally {
        $ackLock.Dispose()
    }

    [IO.File]::Delete($expectedSetup)
    [IO.File]::Delete($expectedAck)
    [IO.Directory]::Delete($expectedCache,$false)
    $productRoot=[IO.Path]::GetDirectoryName($expectedCache)
    if ([IO.Directory]::Exists($productRoot) -and
        -not [IO.Directory]::EnumerateFileSystemEntries($productRoot).GetEnumerator().MoveNext()) {
        [IO.Directory]::Delete($productRoot,$false)
    }
} catch {
    exit 0
} finally {
    if ($ownsMutex -and $null -ne $mutex) {
        try { $mutex.ReleaseMutex() } catch {}
    }
    if ($null -ne $mutex) { $mutex.Dispose() }
    if ($null -ne $identity) { $identity.Dispose() }
}
`
	cmd := newCapturedSetupCommand(
		context.Background(),
		powerShell,
		"-NoProfile",
		"-NonInteractive",
		"-WindowStyle",
		"Hidden",
		"-Command",
		script,
	)
	cmd.Dir = filepath.Dir(powerShell)
	cmd.Env = append(
		os.Environ(),
		"DEFENSECLAW_CLEANUP_ACK="+record.CacheAckPath,
		"DEFENSECLAW_CLEANUP_TRANSACTION_ID="+record.TransactionID,
		"DEFENSECLAW_CLEANUP_PARENT_PID="+fmt.Sprintf("%d", parentPID),
		"DEFENSECLAW_CLEANUP_WAIT_MS="+fmt.Sprintf("%d", waitTimeout.Milliseconds()),
	)
	return cmd
}
