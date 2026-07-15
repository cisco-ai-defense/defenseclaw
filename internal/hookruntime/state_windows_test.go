// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package hookruntime

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	stableRuntimeTransactionOne = "00112233445566778899aabbccddeeff"
	stableRuntimeTransactionTwo = "ffeeddccbbaa99887766554433221100"
)

func testRuntimePaths(t *testing.T) Paths {
	t.Helper()
	root := filepath.Join(t.TempDir(), "DefenseClaw", "HookRuntime")
	return Paths{
		Root:     root,
		Launcher: filepath.Join(root, LauncherName),
		State:    filepath.Join(root, StateName),
	}
}

func writeRuntimeSource(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "packaged-defenseclaw-hook.exe")
	if err := os.WriteFile(path, []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

func writeRuntimeGateway(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, GatewayName)
	if err := os.WriteFile(path, []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestStableRuntimePublishDisableAndReinstall(t *testing.T) {
	paths := testRuntimePaths(t)
	firstSource := writeRuntimeSource(t, "MZ-first-stable-hook")
	firstGateway := writeRuntimeGateway(t, "MZ-first-gateway")
	firstDataRoot := filepath.Join(t.TempDir(), "first-data")
	if err := publishAt(paths, firstSource, firstGateway, firstDataRoot, stableRuntimeTransactionOne); err != nil {
		t.Fatalf("first publish: %v", err)
	}

	first, recognized, err := readTrustedAt(paths, paths.Launcher)
	if err != nil || !recognized || !first.Active() {
		t.Fatalf("first active state: state=%+v recognized=%v err=%v", first, recognized, err)
	}
	if !samePath(first.DataRoot, firstDataRoot) || first.TransactionID != stableRuntimeTransactionOne {
		t.Fatalf("first active generation = %+v", first)
	}
	if !first.ColdStartCapable() || !samePath(first.GatewayPath, firstGateway) {
		t.Fatalf("first generation lacks gateway cold-start identity: %+v", first)
	}
	launcherBeforeUninstall, err := os.ReadFile(paths.Launcher)
	if err != nil {
		t.Fatal(err)
	}

	if err := disableAt(paths, stableRuntimeTransactionTwo); err != nil {
		t.Fatalf("disable: %v", err)
	}
	disabled, recognized, err := readTrustedAt(paths, paths.Launcher)
	if err != nil || !recognized || disabled.Active() || disabled.Status != StatusDisabled {
		t.Fatalf("disabled state: state=%+v recognized=%v err=%v", disabled, recognized, err)
	}
	if disabled.DataRoot != "" || disabled.TransactionID != stableRuntimeTransactionTwo {
		t.Fatalf("disabled generation retained active data: %+v", disabled)
	}
	launcherAfterUninstall, err := os.ReadFile(paths.Launcher)
	if err != nil {
		t.Fatalf("stable launcher was removed by uninstall: %v", err)
	}
	if string(launcherAfterUninstall) != string(launcherBeforeUninstall) {
		t.Fatal("disable mutated the stable launcher")
	}
	// DELETEUSERDATA must not affect the launcher or its disabled state.
	if err := os.RemoveAll(firstDataRoot); err != nil {
		t.Fatal(err)
	}
	if afterDelete, _, err := readTrustedAt(paths, paths.Launcher); err != nil || afterDelete.Active() {
		t.Fatalf("DELETEUSERDATA changed disabled behavior: state=%+v err=%v", afterDelete, err)
	}

	secondSource := writeRuntimeSource(t, "MZ-second-stable-hook")
	secondGateway := writeRuntimeGateway(t, "MZ-second-gateway")
	secondDataRoot := filepath.Join(t.TempDir(), "second-data")
	if err := publishAt(paths, secondSource, secondGateway, secondDataRoot, stableRuntimeTransactionOne); err != nil {
		t.Fatalf("reinstall publish: %v", err)
	}
	reinstalled, recognized, err := readTrustedAt(paths, paths.Launcher)
	if err != nil || !recognized || !reinstalled.Active() {
		t.Fatalf("reinstalled state: state=%+v recognized=%v err=%v", reinstalled, recognized, err)
	}
	if !samePath(reinstalled.DataRoot, secondDataRoot) || !samePath(reinstalled.GatewayPath, secondGateway) ||
		reinstalled.TransactionID != stableRuntimeTransactionOne {
		t.Fatalf("reinstalled generation = %+v", reinstalled)
	}
	launcherAfterReinstall, err := os.ReadFile(paths.Launcher)
	if err != nil || string(launcherAfterReinstall) != "MZ-second-stable-hook" {
		t.Fatalf("reinstall did not refresh launcher: %q err=%v", launcherAfterReinstall, err)
	}
}

func TestStableRuntimeFailsClosedForTamperedLauncherAndState(t *testing.T) {
	paths := testRuntimePaths(t)
	dataRoot := filepath.Join(t.TempDir(), "data")
	gateway := writeRuntimeGateway(t, "MZ-trusted-gateway")
	if err := publishAt(paths, writeRuntimeSource(t, "MZ-trusted"), gateway, dataRoot, stableRuntimeTransactionOne); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(paths.Launcher, []byte("MZ-tampered"), 0o600); err != nil {
		t.Fatal(err)
	}
	if state, recognized, err := readTrustedAt(paths, paths.Launcher); !recognized || err == nil || state.Active() {
		t.Fatalf("tampered launcher was accepted: state=%+v recognized=%v err=%v", state, recognized, err)
	}

	if err := publishAt(paths, writeRuntimeSource(t, "MZ-restored"), gateway, dataRoot, stableRuntimeTransactionTwo); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(paths.State)
	if err != nil {
		t.Fatal(err)
	}
	body = []byte(strings.Replace(string(body), `"status": "active"`, `"status": "unknown"`, 1))
	if err := os.WriteFile(paths.State, body, 0o600); err != nil {
		t.Fatal(err)
	}
	if state, recognized, err := readTrustedAt(paths, paths.Launcher); !recognized || err == nil || state.Active() {
		t.Fatalf("tampered state was accepted: state=%+v recognized=%v err=%v", state, recognized, err)
	}

	outside := filepath.Join(t.TempDir(), LauncherName)
	if _, recognized, err := readTrustedAt(paths, outside); recognized || err != nil {
		t.Fatalf("outside executable recognized=%v err=%v", recognized, err)
	}
}

func TestStableRuntimeMissingLauncherCannotReactivateDisabledState(t *testing.T) {
	paths := testRuntimePaths(t)
	if err := os.MkdirAll(paths.Root, 0o700); err != nil {
		t.Fatal(err)
	}
	// Establish the same private directory contract the installer uses.
	if err := publishAt(
		paths,
		writeRuntimeSource(t, "MZ-old"),
		writeRuntimeGateway(t, "MZ-gateway"),
		filepath.Join(t.TempDir(), "data"),
		stableRuntimeTransactionOne,
	); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(paths.Launcher); err != nil {
		t.Fatal(err)
	}
	if err := disableAt(paths, stableRuntimeTransactionTwo); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(paths.Launcher, []byte("MZ-copied-later"), 0o600); err != nil {
		t.Fatal(err)
	}
	if state, recognized, err := readTrustedAt(paths, paths.Launcher); !recognized || err == nil || state.Active() {
		t.Fatalf("later launcher inherited stale active state: state=%+v recognized=%v err=%v", state, recognized, err)
	}
}

func TestStableRuntimeLegacyActiveStateRemainsReadableWithoutColdStartAuthority(t *testing.T) {
	paths := testRuntimePaths(t)
	state := State{
		SchemaVersion:  LegacySchemaVersion,
		Status:         StatusActive,
		RuntimeRoot:    paths.Root,
		LauncherPath:   paths.Launcher,
		LauncherSHA256: strings.Repeat("a", 64),
		DataRoot:       filepath.Join(t.TempDir(), "legacy-data"),
		TransactionID:  stableRuntimeTransactionOne,
	}
	if err := state.Validate(paths); err != nil {
		t.Fatalf("legacy active state rejected during upgrade: %v", err)
	}
	if state.ColdStartCapable() {
		t.Fatal("legacy state gained gateway start authority without a recorded identity")
	}
}

func TestLockVerifiedGatewayPinsDigestAndReplacement(t *testing.T) {
	paths := testRuntimePaths(t)
	gateway := writeRuntimeGateway(t, "MZ-pinned-gateway")
	if err := publishAt(
		paths,
		writeRuntimeSource(t, "MZ-hook"),
		gateway,
		filepath.Join(t.TempDir(), "data"),
		stableRuntimeTransactionOne,
	); err != nil {
		t.Fatal(err)
	}
	state, _, err := readTrustedAt(paths, paths.Launcher)
	if err != nil {
		t.Fatal(err)
	}
	locked, err := LockVerifiedGateway(state)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(gateway, []byte("MZ-replacement"), 0o700); err == nil {
		_ = locked.Close()
		t.Fatal("gateway replacement succeeded while verified image handle was pinned")
	}
	if err := locked.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(gateway, []byte("MZ-tampered-after-close"), 0o700); err != nil {
		t.Fatal(err)
	}
	if locked, err := LockVerifiedGateway(state); err == nil {
		_ = locked.Close()
		t.Fatal("tampered gateway matched installer-recorded digest")
	}
}
