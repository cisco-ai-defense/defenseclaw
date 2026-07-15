// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type connectorMaintenanceGateway struct {
	path    string
	cleanup func()
}

type connectorMaintenanceGatewayProvider func() (connectorMaintenanceGateway, error)
type connectorMaintenancePayloadLoader func(string) (loadedPayload, error)

// prepareConnectorMaintenanceGateway materializes the gateway carried by the
// running Setup executable into the private installer temp root. Connector
// teardown must not execute the installed copy: that is exactly the payload an
// interrupted install, antivirus quarantine, or local corruption may have
// removed or replaced.
func prepareConnectorMaintenanceGateway() (connectorMaintenanceGateway, error) {
	tempParent, err := defaultPayloadTempRoot()
	if err != nil {
		return connectorMaintenanceGateway{}, err
	}
	return prepareConnectorMaintenanceGatewayAt(tempParent, loadPayload)
}

func prepareConnectorMaintenanceGatewayAt(
	tempParent string,
	load connectorMaintenancePayloadLoader,
) (connectorMaintenanceGateway, error) {
	if err := cleanupStalePayloadTemps(tempParent); err != nil {
		return connectorMaintenanceGateway{}, fmt.Errorf("prepare connector maintenance payload root: %w", err)
	}
	payload, err := load(tempParent)
	if err != nil {
		return connectorMaintenanceGateway{}, fmt.Errorf("load connector maintenance payload: %w", err)
	}
	cleanup := func() {
		// A failed best-effort removal is handled by cleanupStalePayloadTemps on
		// the next Setup invocation. Never turn successful connector cleanup
		// back into user-config residue solely because a scanner retained a file
		// handle after the child process exited.
		cleanupConnectorMaintenancePayload(payload.TempRoot, tempParent)
	}
	fail := func(cause error) (connectorMaintenanceGateway, error) {
		cleanup()
		return connectorMaintenanceGateway{}, cause
	}
	// loadPayload creates and verifies this root, but validate it again at the
	// extraction boundary before creating any child paths. A swapped or custom
	// loader result must not redirect the maintenance binary write through a
	// reparse point or a directory writable by another principal.
	if err := validatePrivateTransactionPath(payload.TempRoot, true); err != nil {
		return fail(fmt.Errorf("validate connector maintenance payload root before extraction: %w", err))
	}
	if err := rejectReparseTree(payload.TempRoot); err != nil {
		return fail(fmt.Errorf("validate connector maintenance payload tree before extraction: %w", err))
	}

	binDir := filepath.Join(payload.TempRoot, "maintenance", "bin")
	if err := os.MkdirAll(binDir, 0o700); err != nil {
		return fail(fmt.Errorf("create connector maintenance binary directory: %w", err))
	}
	if err := extractGateway(payload, binDir); err != nil {
		return fail(fmt.Errorf("extract connector maintenance gateway: %w", err))
	}
	if err := rejectReparseTree(payload.TempRoot); err != nil {
		return fail(fmt.Errorf("validate connector maintenance payload tree: %w", err))
	}
	if err := validatePrivateTransactionPath(payload.TempRoot, true); err != nil {
		return fail(fmt.Errorf("validate connector maintenance payload root: %w", err))
	}
	gatewayPath := filepath.Join(binDir, "defenseclaw-gateway.exe")
	if err := validatePrivateTransactionPath(gatewayPath, false); err != nil {
		return fail(fmt.Errorf("validate connector maintenance gateway: %w", err))
	}
	output, err := runCapturedSetupCommand(
		setupValidationTimeout,
		sanitizePythonEnv(os.Environ()),
		gatewayPath,
		"--version-json",
	)
	if err != nil {
		return fail(fmt.Errorf(
			"validate connector maintenance gateway version: %w: %s",
			err,
			strings.TrimSpace(string(output)),
		))
	}
	if err := validateMachineVersion(
		output,
		"defenseclaw-gateway",
		payload.Manifest.Version,
		payload.Manifest.SourceCommit,
	); err != nil {
		return fail(fmt.Errorf("validate connector maintenance gateway identity: %w", err))
	}
	return connectorMaintenanceGateway{path: gatewayPath, cleanup: cleanup}, nil
}

func cleanupConnectorMaintenancePayload(tempRoot, tempParent string) {
	cleanupConnectorMaintenancePayloadWith(
		tempRoot,
		tempParent,
		removeTransactionTree,
		os.Remove,
		time.Sleep,
	)
}

func cleanupConnectorMaintenancePayloadWith(
	tempRoot, tempParent string,
	removeTree func(string, string) error,
	removeParent func(string) error,
	sleep func(time.Duration),
) {
	for attempt := 0; attempt < installTreeRenameMaxAttempts; attempt++ {
		err := removeTree(tempRoot, tempParent)
		if err == nil || errors.Is(err, os.ErrNotExist) {
			err = removeParent(tempParent)
			if err == nil || errors.Is(err, os.ErrNotExist) {
				return
			}
		}
		if !isTransientInstallTreeRenameError(err) || attempt+1 == installTreeRenameMaxAttempts {
			return
		}
		sleep(installTreeRenameRetryDelay)
	}
}

func reconcileRemovedConnectorsWithMaintenance(
	transaction setupTransaction,
	childEnv []string,
	provide connectorMaintenanceGatewayProvider,
	run connectorLifecycleRunner,
) connectorReconciliationRecorder {
	if len(transaction.PreviousConnectors) == 0 {
		return connectorReconciliationRecorder{}
	}
	maintenance, err := provide()
	if err != nil {
		reconciliation := connectorReconciliationRecorder{}
		for _, connectorName := range transaction.PreviousConnectors {
			configHome := connectorConfigHome(transaction, connectorName, true)
			reconciliation.run(transaction.ID, connectorName, configHome, "payload-missing", func() error {
				return fmt.Errorf("setup-owned connector maintenance payload is unavailable; cleanup was not attempted: %w", err)
			})
		}
		return reconciliation
	}
	if maintenance.cleanup == nil {
		maintenance.cleanup = func() {}
	}
	defer maintenance.cleanup()
	if strings.TrimSpace(maintenance.path) == "" {
		reconciliation := connectorReconciliationRecorder{}
		for _, connectorName := range transaction.PreviousConnectors {
			configHome := connectorConfigHome(transaction, connectorName, true)
			reconciliation.run(transaction.ID, connectorName, configHome, "payload-missing", func() error {
				return errors.New("setup-owned connector maintenance gateway path is empty")
			})
		}
		return reconciliation
	}
	return reconcileRemovedConnectors(transaction, maintenance.path, childEnv, run)
}
