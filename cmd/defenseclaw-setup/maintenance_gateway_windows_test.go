//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"archive/zip"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

const maintenanceGatewayTestVersion = "9.9.9"

func TestMain(m *testing.M) {
	if os.Getenv("DEFENSECLAW_SETUP_MAINTENANCE_TEST_HELPER") == "1" &&
		len(os.Args) == 2 && os.Args[1] == "--version-json" {
		fmt.Printf(`{"schema_version":1,"name":"defenseclaw-gateway","version":%q}`, maintenanceGatewayTestVersion)
		os.Exit(0)
	}
	if os.Getenv("DEFENSECLAW_SETUP_SERVICE_CONTROL_TEST_HELPER") == "1" {
		signal := ""
		switch {
		case len(os.Args) == 2 && os.Args[1] == "stop":
			signal = os.Getenv("DEFENSECLAW_SETUP_TEST_GATEWAY_STOP")
		case len(os.Args) == 3 && os.Args[1] == "watchdog" && os.Args[2] == "stop":
			signal = os.Getenv("DEFENSECLAW_SETUP_TEST_WATCHDOG_STOP")
		}
		if signal != "" {
			if err := os.WriteFile(signal, []byte("stop"), 0o600); err != nil {
				os.Exit(3)
			}
			os.Exit(0)
		}
	}
	os.Exit(m.Run())
}

func writeMaintenanceGatewayArchive(t *testing.T, path, executable string, corrupt bool) {
	t.Helper()
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	writer := zip.NewWriter(file)
	for _, name := range []string{"defenseclaw.exe", "defenseclaw-hook.exe"} {
		entry, createErr := writer.Create(name)
		if createErr != nil {
			_ = writer.Close()
			_ = file.Close()
			t.Fatal(createErr)
		}
		if corrupt {
			if _, err := entry.Write([]byte("not a Windows executable")); err != nil {
				t.Fatal(err)
			}
			continue
		}
		source, openErr := os.Open(executable)
		if openErr != nil {
			t.Fatal(openErr)
		}
		_, copyErr := io.Copy(entry, source)
		closeErr := source.Close()
		if copyErr != nil || closeErr != nil {
			t.Fatal(errors.Join(copyErr, closeErr))
		}
	}
	if err := writer.Close(); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}

func maintenancePayloadLoaderForTest(t *testing.T, executable string, corrupt bool) connectorMaintenancePayloadLoader {
	t.Helper()
	return func(tempParent string) (loadedPayload, error) {
		tempRoot, err := os.MkdirTemp(tempParent, ".DefenseClawSetup.")
		if err != nil {
			return loadedPayload{}, err
		}
		payloadRoot := filepath.Join(tempRoot, "payload")
		if err := os.MkdirAll(payloadRoot, 0o700); err != nil {
			return loadedPayload{}, err
		}
		archive := filepath.Join(payloadRoot, "gateway.zip")
		writeMaintenanceGatewayArchive(t, archive, executable, corrupt)
		return loadedPayload{
			Root:     payloadRoot,
			TempRoot: tempRoot,
			Manifest: payloadManifest{
				Version:        maintenanceGatewayTestVersion,
				GatewayArchive: filepath.Base(archive),
			},
		}, nil
	}
}

func TestPrepareConnectorMaintenanceGatewayExtractsValidatesAndCleansPrivateCopy(t *testing.T) {
	t.Setenv("DEFENSECLAW_SETUP_MAINTENANCE_TEST_HELPER", "1")
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	tempParent := filepath.Join(t.TempDir(), "InstallerTemp")
	maintenance, err := prepareConnectorMaintenanceGatewayAt(
		tempParent,
		maintenancePayloadLoaderForTest(t, executable, false),
	)
	if err != nil {
		t.Fatalf("prepare connector maintenance gateway: %v", err)
	}
	if samePath(maintenance.path, executable) || !strings.HasPrefix(
		strings.ToLower(maintenance.path),
		strings.ToLower(tempParent)+string(os.PathSeparator),
	) {
		t.Fatalf("maintenance gateway path = %q, want a private extracted copy", maintenance.path)
	}
	if err := validatePrivateTransactionPath(maintenance.path, false); err != nil {
		t.Fatalf("maintenance gateway is not private: %v", err)
	}
	maintenance.cleanup()
	if _, err := os.Lstat(tempParent); !os.IsNotExist(err) {
		t.Fatalf("maintenance payload survived cleanup: %v", err)
	}
}

func TestCleanupConnectorMaintenancePayloadRetriesTransientLocks(t *testing.T) {
	var treeAttempts, parentAttempts int
	var sleeps []time.Duration
	cleanupConnectorMaintenancePayloadWith(
		`C:\\private\\payload`,
		`C:\\private`,
		func(_, _ string) error {
			treeAttempts++
			if treeAttempts == 1 {
				return &os.PathError{Op: "remove", Path: "gateway.exe", Err: syscall.Errno(32)}
			}
			return nil
		},
		func(string) error {
			parentAttempts++
			if parentAttempts == 1 {
				return &os.PathError{Op: "remove", Path: "private", Err: syscall.Errno(5)}
			}
			return nil
		},
		func(delay time.Duration) { sleeps = append(sleeps, delay) },
	)

	if treeAttempts != 3 || parentAttempts != 2 {
		t.Fatalf("cleanup attempts = tree %d, parent %d; want 3, 2", treeAttempts, parentAttempts)
	}
	if len(sleeps) != 2 || sleeps[0] != installTreeRenameRetryDelay || sleeps[1] != installTreeRenameRetryDelay {
		t.Fatalf("cleanup retry delays = %v", sleeps)
	}
}

func TestPrepareConnectorMaintenanceGatewayRejectsCorruptEmbeddedExecutable(t *testing.T) {
	t.Setenv("DEFENSECLAW_SETUP_MAINTENANCE_TEST_HELPER", "1")
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	tempParent := filepath.Join(t.TempDir(), "InstallerTemp")
	if _, err := prepareConnectorMaintenanceGatewayAt(
		tempParent,
		maintenancePayloadLoaderForTest(t, executable, true),
	); err == nil {
		t.Fatal("corrupt embedded connector maintenance gateway was accepted")
	}
	if _, err := os.Lstat(tempParent); !os.IsNotExist(err) {
		t.Fatalf("rejected maintenance payload survived cleanup: %v", err)
	}
}

func TestPrepareConnectorMaintenanceGatewayRejectsReparseRootBeforeExtraction(t *testing.T) {
	target := filepath.Join(t.TempDir(), "redirect-target")
	if err := os.MkdirAll(filepath.Join(target, "payload"), 0o700); err != nil {
		t.Fatal(err)
	}
	tempParent := filepath.Join(t.TempDir(), "InstallerTemp")
	if err := os.MkdirAll(tempParent, 0o700); err != nil {
		t.Fatal(err)
	}
	redirect := filepath.Join(tempParent, ".DefenseClawSetup.redirect")
	t.Cleanup(func() { _ = os.Remove(redirect) })

	loader := func(string) (loadedPayload, error) {
		if err := os.Symlink(target, redirect); err != nil {
			if output, junctionErr := exec.Command(
				"cmd.exe", "/D", "/C", "mklink", "/J", redirect, target,
			).CombinedOutput(); junctionErr != nil {
				return loadedPayload{}, fmt.Errorf(
					"create maintenance reparse fixture after symlink error %v: %w: %s",
					err, junctionErr, output,
				)
			}
		}
		return loadedPayload{
			Root:     filepath.Join(redirect, "payload"),
			TempRoot: redirect,
			Manifest: payloadManifest{
				Version:        maintenanceGatewayTestVersion,
				GatewayArchive: "gateway.zip",
			},
		}, nil
	}
	if _, err := prepareConnectorMaintenanceGatewayAt(tempParent, loader); err == nil ||
		!strings.Contains(err.Error(), "before extraction") {
		t.Fatalf("reparse maintenance root error = %v, want pre-extraction validation failure", err)
	}
	if _, err := os.Lstat(filepath.Join(target, "maintenance")); !os.IsNotExist(err) {
		t.Fatalf("maintenance extraction wrote through rejected reparse root: %v", err)
	}
}
