// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"time"

	"golang.org/x/sys/windows"

	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/processutil"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

var (
	enterpriseSetupArmUninstallRecovery = armStandaloneUninstallRecovery
	setupRecoveryStart                  = processutil.StartIndependent
	setupRecoveryOpenParent             = openStandaloneSetupParent
	setupRecoveryLayout                 = managed.StandaloneWindowsLayout
	setupRecoveryNeeded                 = standaloneUninstallRecoveryNeeded
	setupRecoveryReplay                 = replayStandaloneSetupTransaction
)

// armStandaloneUninstallRecovery runs before the lifecycle worker. A killed
// Setup must not strand a transaction after the worker removed managed hooks.
// The watcher must outlive Setup's process job (processutil.StartIndependent),
// including the unreadable job of the documented LocalSystem scheduled task
// (GAP-0960).
func armStandaloneUninstallRecovery() error {
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	child := exec.Command(executable, "--internal-recover-after-parent", strconv.Itoa(os.Getpid()))
	child.Dir = filepath.Dir(executable)
	ready, err := child.StdoutPipe()
	if err != nil {
		return fmt.Errorf("create uninstall recovery readiness pipe: %w", err)
	}
	if err := setupRecoveryStart(child); err != nil {
		_ = ready.Close()
		return fmt.Errorf("start uninstall recovery: %w", err)
	}
	// Do not start the worker merely because CreateProcess succeeded. An
	// immediately failing watcher would leave a killed Setup without recovery.
	result := make(chan error, 1)
	go func() {
		marker := make([]byte, len("READY\n"))
		_, readErr := io.ReadFull(ready, marker)
		if readErr == nil && string(marker) != "READY\n" {
			readErr = errors.New("uninstall recovery sent an invalid readiness marker")
		}
		result <- readErr
	}()
	select {
	case err = <-result:
	case <-time.After(30 * time.Second):
		err = errors.New("uninstall recovery did not become ready within 30 seconds")
	}
	if err != nil {
		_ = child.Process.Kill()
		_ = ready.Close()
		_ = child.Wait()
		return fmt.Errorf("uninstall recovery was not armed: %w", err)
	}
	_ = ready.Close()
	return child.Process.Release()
}

func runStandaloneSetupRecoveryWatchdog(parentArgument string, stdout, stderr io.Writer) int {
	parentPID, err := strconv.Atoi(parentArgument)
	if err != nil || parentPID <= 0 || parentPID == os.Getpid() {
		return enterpriseInvalidArgsExitCode
	}
	parent, err := setupRecoveryOpenParent(parentPID)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return enterpriseFailureExitCode
	}
	defer func() { _ = parent.Close() }()
	if _, err := io.WriteString(stdout, "READY\n"); err != nil {
		return enterpriseFailureExitCode
	}
	if err := parent.Wait(); err != nil {
		fmt.Fprintln(stderr, err)
		return enterpriseFailureExitCode
	}
	needed, err := setupRecoveryNeeded()
	if err != nil {
		fmt.Fprintln(stderr, err)
		return enterpriseFailureExitCode
	}
	if !needed {
		return 0
	}
	if err := setupRecoveryReplay(); err != nil {
		fmt.Fprintln(stderr, err)
		return enterpriseFailureExitCode
	}
	return 0
}

// A committed uninstall keeps its trusted tombstone until postcommit hook
// cleanup and any recorded purge finish; a settled state-keeping uninstall
// keeps it for good, so only an unsettled tombstone is replayed. A completed
// purge has no record; an ordinary refusal still has installed metadata.
// These are read-only exits for the watcher, so they cannot recreate a
// lifecycle directory or hooks.
func standaloneUninstallRecoveryNeeded() (bool, error) {
	layout, err := setupRecoveryLayout()
	if err != nil {
		return false, err
	}
	path := filepath.Join(layout.LifecycleDir, "pending.json")
	if _, err := os.Lstat(path); err == nil {
		if err := managed.ValidateTrustedFilePath(path, "standalone pending transaction"); err != nil {
			return false, err
		}
		return true, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return false, err
	}
	deployment, err := standaloneSetupDeployment()
	if err != nil {
		return false, err
	}
	if deployment.State == winpath.EnterpriseDeploymentUnknown {
		return false, errors.New("cannot prove standalone uninstall recovery is settled: deployment metadata is unreadable")
	}
	if deployment.State != winpath.EnterpriseDeploymentTombstone {
		return false, nil
	}
	return standaloneCommittedUninstallUnsettled(layout, deployment.MetadataPath)
}

type standaloneSetupParent interface {
	Wait() error
	Close() error
}

type standaloneSetupParentHandle struct{ handle windows.Handle }

func openStandaloneSetupParent(pid int) (standaloneSetupParent, error) {
	handle, err := windows.OpenProcess(windows.SYNCHRONIZE, false, uint32(pid))
	if errors.Is(err, windows.ERROR_INVALID_PARAMETER) {
		return standaloneSetupParentHandle{}, nil // Parent already exited.
	}
	if err != nil {
		return nil, fmt.Errorf("open uninstall Setup parent before arming recovery: %w", err)
	}
	return standaloneSetupParentHandle{handle: handle}, nil
}

func (parent standaloneSetupParentHandle) Wait() error {
	if parent.handle == 0 {
		return nil
	}
	result, err := windows.WaitForSingleObject(parent.handle, windows.INFINITE)
	if err != nil {
		return fmt.Errorf("wait for uninstall Setup parent: %w", err)
	}
	if result != uint32(windows.WAIT_OBJECT_0) {
		return fmt.Errorf("wait for uninstall Setup parent: unexpected result %d", result)
	}
	return nil
}

func (parent standaloneSetupParentHandle) Close() error {
	if parent.handle == 0 {
		return nil
	}
	return windows.CloseHandle(parent.handle)
}

func replayStandaloneSetupTransaction() error {
	opts := enterpriseSetupOptions{Action: "recover", Standalone: true, JSON: true, LifecycleTimeout: 30 * time.Minute}
	var output bytes.Buffer
	code, err := executeEnterpriseSetup(context.Background(), opts, &output, io.Discard)
	if err != nil {
		return err
	}
	if code != 0 {
		return fmt.Errorf("uninstall transaction recovery exited %d", code)
	}
	var report enterprisestatus.Result
	if err := json.Unmarshal(output.Bytes(), &report); err != nil {
		return fmt.Errorf("decode uninstall transaction recovery: %w", err)
	}
	return proveStandaloneUninstallRecovery(report)
}

func proveStandaloneUninstallRecovery(report enterprisestatus.Result) error {
	if report.SchemaVersion != 2 || report.Action != "recover" || report.Profile != managed.ProfileStandalone ||
		!report.OK || report.TransactionPending || report.ExitCode != 0 || len(report.Errors) != 0 {
		return errors.New("uninstall recovery did not prove a settled installation or completed uninstall")
	}
	if !report.Installed {
		absent := make(map[string]bool, 4)
		for _, service := range report.Services {
			if service.State != "absent" {
				return errors.New("uninstall recovery left a managed service behind")
			}
			absent[service.Kind] = true
		}
		for _, kind := range []string{"gateway", "guardian", "enumerator", "sensor_helper"} {
			if !absent[kind] {
				return fmt.Errorf("uninstall recovery did not prove %s service absent", kind)
			}
		}
		return nil
	}
	gateway, guardian := false, false
	for _, service := range report.Services {
		if service.Kind == "gateway" && service.State == "running" {
			gateway = true
		}
		if service.Kind == "guardian" && service.State == "running" {
			guardian = true
		}
	}
	if !gateway || !guardian {
		return errors.New("uninstall recovery left a managed service stopped")
	}
	return nil
}
