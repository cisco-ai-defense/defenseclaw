// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func TestReadManagedPIDRecordTreatsMissingPathAsAbsent(t *testing.T) {
	pidPath := filepath.Join(t.TempDir(), "watchdog.pid")
	state, exists, err := readManagedPIDRecord(pidPath, false)
	if err != nil {
		t.Fatal(err)
	}
	if exists || state != (pidState{}) {
		t.Fatalf("missing PID record returned state=%+v exists=%t", state, exists)
	}
}

func TestReadManagedPIDRecordReturnsDecodedState(t *testing.T) {
	pidPath := filepath.Join(t.TempDir(), "watchdog.pid")
	want := pidState{
		PID:           4242,
		Executable:    `C:\DefenseClaw\gateway.exe`,
		StartIdentity: "start-identity",
	}
	writeManagedPIDRecordTestFixture(t, pidPath, want)

	got, exists, err := readManagedPIDRecord(pidPath, false)
	if err != nil {
		t.Fatal(err)
	}
	if !exists || got != want {
		t.Fatalf("valid PID record returned state=%+v exists=%t; want state=%+v exists=true", got, exists, want)
	}
}

func TestReadManagedPIDRecordWaitsForInPlacePublication(t *testing.T) {
	pidPath := filepath.Join(t.TempDir(), "watchdog.pid")
	if err := os.WriteFile(pidPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	want := pidState{
		PID:           4242,
		Executable:    `C:\DefenseClaw\gateway.exe`,
		StartIdentity: "start-identity",
	}
	retryStarted := make(chan struct{})
	publicationComplete := make(chan struct{})
	type result struct {
		state  pidState
		exists bool
		err    error
	}
	resultCh := make(chan result, 1)
	go func() {
		state, exists, err := readManagedPIDRecordWithPolicy(pidPath, true, 2, func() {
			close(retryStarted)
			<-publicationComplete
		})
		resultCh <- result{state: state, exists: exists, err: err}
	}()

	select {
	case <-retryStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("reader did not observe the truncated in-flight publication")
	}
	data, err := json.Marshal(want)
	if err != nil {
		close(publicationComplete)
		t.Fatal(err)
	}
	err = os.WriteFile(pidPath, data, 0o600)
	close(publicationComplete)
	if err != nil {
		t.Fatal(err)
	}

	select {
	case got := <-resultCh:
		if got.err != nil {
			t.Fatal(got.err)
		}
		if !got.exists || got.state != want {
			t.Fatalf(
				"published PID record returned state=%+v exists=%t; want state=%+v exists=true",
				got.state,
				got.exists,
				want,
			)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("reader did not finish after publication completed")
	}
}

func TestReadManagedPIDRecordRejectsPersistentMalformedRecord(t *testing.T) {
	pidPath := filepath.Join(t.TempDir(), "watchdog.pid")
	if err := os.WriteFile(pidPath, []byte(`{"pid":`), 0o600); err != nil {
		t.Fatal(err)
	}
	retries := 0
	_, exists, err := readManagedPIDRecordWithPolicy(pidPath, true, 3, func() {
		retries++
	})
	if exists {
		t.Fatal("malformed PID record was reported as usable")
	}
	if err == nil || !strings.Contains(err.Error(), "unexpected end of JSON input") {
		t.Fatalf("persistent malformed PID record error = %v", err)
	}
	if retries != 2 {
		t.Fatalf("publication retries = %d, want 2", retries)
	}
}

func TestReadManagedPIDRecordDoesNotRetrySemanticCorruption(t *testing.T) {
	pidPath := filepath.Join(t.TempDir(), "watchdog.pid")
	if err := os.WriteFile(pidPath, []byte(`{"pid":"bad"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	retries := 0
	_, exists, err := readManagedPIDRecordWithPolicy(pidPath, true, 3, func() {
		retries++
	})
	if exists {
		t.Fatal("semantically invalid PID record was reported as usable")
	}
	var typeErr *json.UnmarshalTypeError
	if !errors.As(err, &typeErr) {
		t.Fatalf("semantic corruption error = %T %v, want *json.UnmarshalTypeError", err, err)
	}
	if retries != 0 {
		t.Fatalf("semantic corruption retries = %d, want 0", retries)
	}
}

func TestReadManagedGatewayPIDRecordDoesNotRetrySyntaxError(t *testing.T) {
	pidPath := filepath.Join(t.TempDir(), "gateway.pid")
	if err := os.WriteFile(pidPath, []byte(`{"pid":`), 0o600); err != nil {
		t.Fatal(err)
	}
	retries := 0
	_, exists, err := readManagedPIDRecordWithPolicy(pidPath, false, 3, func() {
		retries++
	})
	if exists {
		t.Fatal("malformed gateway PID record was reported as usable")
	}
	if err == nil || !strings.Contains(err.Error(), "unexpected end of JSON input") {
		t.Fatalf("gateway syntax error = %v", err)
	}
	if retries != 0 {
		t.Fatalf("gateway syntax retries = %d, want 0", retries)
	}
}

func TestManagedPIDRecordPublicationDoesNotRetryCloseFailure(t *testing.T) {
	syntaxErr := &json.SyntaxError{Offset: 1}
	if managedPIDRecordPublicationInFlight(syntaxErr, errors.New("close failed")) {
		t.Fatal("JSON syntax error joined with close failure was treated as retryable")
	}
	if !managedPIDRecordPublicationInFlight(syntaxErr, nil) {
		t.Fatal("isolated JSON syntax error was not treated as retryable")
	}
}

func TestManagedPIDRecordAbsentErrorsIncludeDeletePending(t *testing.T) {
	for name, err := range map[string]error{
		"file missing":   windows.ERROR_FILE_NOT_FOUND,
		"path missing":   windows.ERROR_PATH_NOT_FOUND,
		"delete pending": windows.ERROR_DELETE_PENDING,
	} {
		t.Run(name, func(t *testing.T) {
			if !isManagedPIDRecordAbsentError(fmt.Errorf("open PID record: %w", err)) {
				t.Fatalf("%v was not treated as logical absence", err)
			}
		})
	}
	if isManagedPIDRecordAbsentError(windows.ERROR_ACCESS_DENIED) {
		t.Fatal("access denied was treated as logical absence")
	}
}

func TestDecodeManagedPIDRecordUsesOpenedHandleAfterPathReplacement(t *testing.T) {
	dataRoot := t.TempDir()
	pidPath := filepath.Join(dataRoot, "watchdog.pid")
	openedPath := filepath.Join(dataRoot, "watchdog.opened.pid")
	original := pidState{
		PID:           101,
		Executable:    `C:\DefenseClaw\original.exe`,
		StartIdentity: "original-start",
	}
	replacement := pidState{
		PID:           202,
		Executable:    `C:\DefenseClaw\replacement.exe`,
		StartIdentity: "replacement-start",
	}
	writeManagedPIDRecordTestFixture(t, pidPath, original)

	file, exists, err := openManagedPIDRecord(pidPath)
	if err != nil {
		t.Fatal(err)
	}
	if !exists || file == nil {
		t.Fatal("existing PID record was not opened")
	}
	defer func() {
		if err := file.Close(); err != nil {
			t.Errorf("close opened PID record: %v", err)
		}
	}()

	// FILE_SHARE_DELETE permits the publisher to atomically replace the record
	// while the verifier retains an identity-stable handle to the old object.
	if err := os.Rename(pidPath, openedPath); err != nil {
		t.Fatalf("rename opened PID record: %v", err)
	}
	writeManagedPIDRecordTestFixture(t, pidPath, replacement)

	got, err := decodeManagedPIDRecord(file, pidPath)
	if err != nil {
		t.Fatal(err)
	}
	if got != original {
		t.Fatalf("decoded replacement path instead of opened record: got %+v want %+v", got, original)
	}
}

func TestOpenManagedPIDRecordRejectsDirectory(t *testing.T) {
	pidPath := t.TempDir()
	file, exists, err := openManagedPIDRecord(pidPath)
	if file != nil {
		_ = file.Close()
		t.Fatal("directory PID record returned an open file")
	}
	if exists {
		t.Fatal("directory PID record was reported as usable")
	}
	if err == nil || !strings.Contains(err.Error(), "is not a regular file") {
		t.Fatalf("directory PID record error = %v", err)
	}
}

func TestOpenManagedPIDRecordRejectsReparsePoint(t *testing.T) {
	dataRoot := t.TempDir()
	target := filepath.Join(dataRoot, "target.pid")
	pidPath := filepath.Join(dataRoot, "watchdog.pid")
	writeManagedPIDRecordTestFixture(t, target, pidState{
		PID:        101,
		Executable: `C:\DefenseClaw\gateway.exe`,
	})
	if err := os.Symlink(target, pidPath); err != nil {
		t.Skipf("creating a file symlink requires Windows Developer Mode or elevation: %v", err)
	}

	file, exists, err := openManagedPIDRecord(pidPath)
	if file != nil {
		_ = file.Close()
		t.Fatal("reparse-point PID record returned an open file")
	}
	if exists {
		t.Fatal("reparse-point PID record was reported as usable")
	}
	if err == nil || !strings.Contains(err.Error(), "is a reparse point") {
		t.Fatalf("reparse-point error = %v", err)
	}
}

func TestReadManagedPIDRecordRejectsOversizeRecord(t *testing.T) {
	pidPath := filepath.Join(t.TempDir(), "watchdog.pid")
	if err := os.WriteFile(
		pidPath,
		[]byte(strings.Repeat("x", maxManagedPIDRecordBytes+1)),
		0o600,
	); err != nil {
		t.Fatal(err)
	}

	_, exists, err := readManagedPIDRecord(pidPath, false)
	if exists {
		t.Fatal("oversize PID record was reported as usable")
	}
	if err == nil || !strings.Contains(err.Error(), "exceeds 65536 bytes") {
		t.Fatalf("oversize PID record error = %v", err)
	}
}

func writeManagedPIDRecordTestFixture(t *testing.T, path string, state pidState) {
	t.Helper()
	data, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}
