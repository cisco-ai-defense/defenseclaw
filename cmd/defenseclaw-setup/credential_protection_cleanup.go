// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type credentialCleanupRuntime struct {
	root    string
	cleanup func()
}

type credentialCleanupRuntimeProvider func(setupTransaction) (credentialCleanupRuntime, error)
type credentialCleanupCommandRunner func(credentialCleanupRuntime, setupTransaction) error

func prepareCredentialCleanupRuntime(transaction setupTransaction) (credentialCleanupRuntime, error) {
	tempParent, err := defaultPayloadTempRoot()
	if err != nil {
		return credentialCleanupRuntime{}, err
	}
	if err := cleanupStalePayloadTemps(tempParent); err != nil {
		return credentialCleanupRuntime{}, fmt.Errorf("prepare credential cleanup payload root: %w", err)
	}
	payload, err := loadPayload(tempParent)
	if err != nil {
		return credentialCleanupRuntime{}, fmt.Errorf("load credential cleanup payload: %w", err)
	}
	cleanup := func() {
		cleanupConnectorMaintenancePayload(payload.TempRoot, tempParent)
	}
	fail := func(cause error) (credentialCleanupRuntime, error) {
		cleanup()
		return credentialCleanupRuntime{}, cause
	}

	runtimeRoot := filepath.Join(payload.TempRoot, "credential-cleanup-runtime")
	opts := options{Connector: "none", Mode: "observe", Quiet: true}
	if err := stageInstallTree(
		payload,
		runtimeRoot,
		runtimeRoot,
		transaction.DataRoot,
		"",
		transaction.ID,
		false,
		false,
		false,
		opts,
	); err != nil {
		return fail(fmt.Errorf("stage credential cleanup runtime: %w", err))
	}
	if err := validateInstall(runtimeRoot, payload.Manifest.Version); err != nil {
		return fail(fmt.Errorf("validate credential cleanup runtime: %w", err))
	}
	return credentialCleanupRuntime{root: runtimeRoot, cleanup: cleanup}, nil
}

func runCredentialCleanupCommand(runtime credentialCleanupRuntime, transaction setupTransaction) error {
	if strings.TrimSpace(runtime.root) == "" {
		return errors.New("credential cleanup runtime path is empty")
	}
	output, err := runCapturedSetupCommand(
		setupConfigurationTimeout,
		transactionPreviousChildEnv(transaction),
		filepath.Join(runtime.root, "bin", "defenseclaw.exe"),
		credentialProtectionSetupArgs(false)...,
	)
	if err != nil {
		return fmt.Errorf("credential protection cleanup failed: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

func cleanupCredentialProtectionWithMaintenance(
	transaction setupTransaction,
	provide credentialCleanupRuntimeProvider,
	run credentialCleanupCommandRunner,
) error {
	if _, err := os.Lstat(transaction.DataRoot); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return fmt.Errorf("inspect credential protection data root: %w", err)
	}

	runtime, err := provide(transaction)
	if err != nil {
		return err
	}
	if runtime.cleanup == nil {
		runtime.cleanup = func() {}
	}
	defer runtime.cleanup()
	return run(runtime, transaction)
}

func cleanupCredentialProtectionForUninstall(transaction setupTransaction) error {
	return cleanupCredentialProtectionWithMaintenance(
		transaction,
		prepareCredentialCleanupRuntime,
		runCredentialCleanupCommand,
	)
}
