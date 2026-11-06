// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package safefile

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDataFilePublicationUsesTransactionAndImageTwinStaysPlain(t *testing.T) {
	if !dataTransactionsAvailable() {
		t.Skip("Windows file transactions are unavailable on this host")
	}
	for _, tc := range []struct {
		name            string
		old, next       []byte
		wantTransaction bool
	}{
		{name: "data", old: []byte(`{"version":1}`), next: []byte(`{"version":2}`), wantTransaction: true},
		{name: "image", old: []byte("MZold"), next: []byte("MZnew")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			target := filepath.Join(dir, "stable")
			stage := filepath.Join(dir, "staged")
			if err := os.WriteFile(target, tc.old, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(stage, tc.next, 0o600); err != nil {
				t.Fatal(err)
			}
			var inTransaction bool
			err := InDataFileTransaction(stage, target, func() error {
				current, _, _ := dataGetCurrentTransaction.Call()
				inTransaction = current != 0
				return ReplaceFileAtomically(stage, target)
			})
			if err != nil {
				t.Fatal(err)
			}
			if inTransaction != tc.wantTransaction {
				t.Fatalf("transaction active = %t, want %t", inTransaction, tc.wantTransaction)
			}
			got, err := os.ReadFile(target)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != string(tc.next) {
				t.Fatalf("published %q, want %q", got, tc.next)
			}
		})
	}
}

func TestDataFileTransactionRollsBackAnUnsuccessfulPublication(t *testing.T) {
	if !dataTransactionsAvailable() {
		t.Skip("Windows file transactions are unavailable on this host")
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "stable.json")
	stage := filepath.Join(dir, "stage.json")
	if err := os.WriteFile(target, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(stage, []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}
	const failed = "validation failed"
	err := InDataFileTransaction(stage, target, func() error {
		if err := ReplaceFileAtomically(stage, target); err != nil {
			return err
		}
		return os.ErrInvalid
	})
	if err == nil {
		t.Fatal(failed)
	}
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "old" {
		t.Fatalf("rolled-back target = %q", got)
	}
	if _, err := os.Stat(stage); err != nil {
		t.Fatalf("rolled-back stage: %v", err)
	}
}
