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
	"path/filepath"
	"strings"
	"testing"
)

const maintenanceGatewayTestVersion = "9.9.9"

func TestMain(m *testing.M) {
	if os.Getenv("DEFENSECLAW_SETUP_MAINTENANCE_TEST_HELPER") == "1" &&
		len(os.Args) == 2 && os.Args[1] == "--version-json" {
		fmt.Printf(`{"schema_version":1,"name":"defenseclaw-gateway","version":%q}`, maintenanceGatewayTestVersion)
		os.Exit(0)
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
