// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestProcessIdentityLongPathHelper(t *testing.T) {
	if os.Getenv("DEFENSECLAW_LONG_PATH_HELPER") != "1" {
		return
	}
	fmt.Println("READY")
	_, _ = io.Copy(io.Discard, os.Stdin)
}

func TestProcessIdentitySupportsExecutablePathBeyondMAXPath(t *testing.T) {
	root := t.TempDir()
	for len(root) < 285 {
		root = filepath.Join(root, "defenseclaw-long-path-segment")
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	executable := filepath.Join(root, "defenseclaw-setup-test.exe")
	if err := copyFile(os.Args[0], executable); err != nil {
		t.Fatal(err)
	}
	if len(executable) <= 260 {
		t.Fatalf("fixture path length = %d, want > 260", len(executable))
	}

	cmd := exec.Command(executable, "-test.run=^TestProcessIdentityLongPathHelper$")
	cmd.Env = append(os.Environ(), "DEFENSECLAW_LONG_PATH_HELPER=1")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = stdin.Close()
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
	})
	line, err := bufio.NewReader(stdout).ReadString('\n')
	if err != nil || strings.TrimSpace(line) != "READY" {
		t.Fatalf("long-path helper readiness = %q, %v", line, err)
	}

	livePath, _, err := processIdentity(uint32(cmd.Process.Pid))
	if err != nil {
		t.Fatalf("processIdentity: %v", err)
	}
	if !samePath(livePath, executable) {
		t.Fatalf("process path = %q, want %q", livePath, executable)
	}
	if err := stdin.Close(); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Wait(); err != nil {
		t.Fatal(err)
	}
}

func TestDurableJournalSupportsTransactionRootBeyondMAXPath(t *testing.T) {
	root := t.TempDir()
	for len(root) < 285 {
		root = filepath.Join(root, "defenseclaw-installer-state-segment")
	}
	path := filepath.Join(root, "setup-transaction.json")
	if len(path) <= 260 {
		t.Fatalf("fixture path length = %d, want > 260", len(path))
	}
	installRoot, dataRoot, maintenancePath := testTransactionRoots(t)
	transaction := testSetupTransactionForRoots("install", installRoot, dataRoot, maintenancePath, nil)
	journal := setupJournal{
		SchemaVersion: setupJournalSchemaVersion,
		Phase:         setupPhaseIntent,
		Transaction:   transaction,
	}
	if err := writeDurableJournal(path, journal, false); err != nil {
		t.Fatalf("write long-path intent: %v", err)
	}
	journal.Phase = setupPhaseCommitted
	if err := writeDurableJournal(path, journal, true); err != nil {
		t.Fatalf("replace long-path journal: %v", err)
	}
	loaded, err := readSetupJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded == nil || loaded.Phase != setupPhaseCommitted || !setupTransactionsEqual(loaded.Transaction, transaction) {
		t.Fatalf("long-path journal = %#v", loaded)
	}
}
