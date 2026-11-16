// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterprisepolicy

import (
	"os"
	"strings"
	"testing"
)

// untrustedCascadeOptions turns the trust rules on with the test user as the
// only trusted owner, so a group/other-writable file is an untrusted one.
func untrustedCascadeOptions(t *testing.T) Options {
	t.Helper()
	opts := publishTestOptions(t)
	opts.SkipTrustChecks = false
	previous := trustedOwner
	trustedOwner = func(uid uint32) bool { return uid == uint32(os.Getuid()) }
	t.Cleanup(func() { trustedOwner = previous })
	return opts
}

func writeUntrustedCascadeFile(t *testing.T, path, content string) {
	t.Helper()
	writeFile(t, path, content)
	if err := os.Chmod(path, 0o666); err != nil {
		t.Fatal(err)
	}
}

// A refusal an earlier release wrote can sit in a file that later became
// writable by a standard user. DefenseClaw does not edit such a file on a
// guess, so verify, and ensure without a record of what it published, must
// say the refusal is still there and stay incomplete, not report a clean
// policy. Ensure with the matching ownership record restores the file the
// release published, which withdraws the refusal.
func TestDevinCascadeReportsAnEarlierRefusalInAnUntrustedFile(t *testing.T) {
	for _, recorded := range []bool{false, true} {
		name := "no ownership record"
		if recorded {
			name = "matching ownership record"
		}
		t.Run(name, func(t *testing.T) {
			opts := untrustedCascadeOptions(t)
			legacy, err := devinCascadeLegacyHooksPath(opts)
			if err != nil {
				t.Fatal(err)
			}
			earlier := earlierReleaseCascadeFile(t, opts, legacy, adminCascadeHooks)
			writeUntrustedCascadeFile(t, legacy, earlier)
			if recorded {
				record := &ownershipRecord{Connector: devinCascadeLegacyRecord, Path: legacy, PostimageSHA256: sha256Hex([]byte(earlier))}
				if err := saveRecord(opts, record); err != nil {
					t.Fatal(err)
				}
			}
			verify, err := VerifyAll(opts, []string{"devin"})
			if err != nil {
				t.Fatal(err)
			}
			requireUntrustedRefusalReported(t, "verify", verify)
			if data, _ := os.ReadFile(legacy); string(data) != earlier {
				t.Fatalf("verify edited an untrusted file: %s", data)
			}
			ensure, err := Publish(opts, []string{"devin"})
			if err != nil {
				t.Fatal(err)
			}
			if !recorded {
				requireUntrustedRefusalReported(t, "ensure", ensure)
				if data, _ := os.ReadFile(legacy); string(data) != earlier {
					t.Fatalf("ensure edited an untrusted file it never published: %s", data)
				}
				return
			}
			if state := devinCascadeStateOf(t, ensure.States); !ensure.Complete() || len(state.Conflicts) != 0 {
				t.Fatalf("ensure left the recorded refusal: complete=%v state=%+v", ensure.Complete(), state)
			}
			if data, err := os.ReadFile(legacy); err == nil && strings.Contains(string(data), devinCascadeMessage) {
				t.Fatalf("the recorded refusal is still in the file: %s", data)
			}
		})
	}
}

func requireUntrustedRefusalReported(t *testing.T, label string, result Result) {
	t.Helper()
	state := devinCascadeStateOf(t, result.States)
	if result.Complete() || state.Covered || state.Route != RouteMachinePolicy || len(state.Conflicts) == 0 || state.OwnedEntries == 0 {
		t.Fatalf("%s accepted an untrusted file that still refuses current Devin: complete=%v state=%+v", label, result.Complete(), state)
	}
	if !strings.Contains(strings.Join(state.Conflicts, " "), "not administrator-controlled") {
		t.Fatalf("%s does not say why the file is left alone: %v", label, state.Conflicts)
	}
}

// A file DefenseClaw cannot read or parse cannot be proved clean either.
func TestDevinCascadeReportsAnUntrustedFileItCannotParse(t *testing.T) {
	opts := untrustedCascadeOptions(t)
	devin, err := DevinSystemHooksPath(opts)
	if err != nil {
		t.Fatal(err)
	}
	writeUntrustedCascadeFile(t, devin, "{ not json")
	result, err := VerifyAll(opts, []string{"devin"})
	if err != nil {
		t.Fatal(err)
	}
	if state := devinCascadeStateOf(t, result.States); result.Complete() || len(state.Conflicts) == 0 {
		t.Fatalf("an unreadable untrusted file passed: complete=%v state=%+v", result.Complete(), state)
	}
}

// Benign twin: an untrusted file that carries no earlier refusal is not a
// DefenseClaw conflict, as DefenseClaw publishes nothing there; it is noted.
func TestDevinCascadeNotesAnUntrustedFileWithoutTheRefusal(t *testing.T) {
	opts := untrustedCascadeOptions(t)
	legacy, err := devinCascadeLegacyHooksPath(opts)
	if err != nil {
		t.Fatal(err)
	}
	writeUntrustedCascadeFile(t, legacy, adminCascadeHooks)
	for label, run := range map[string]func(Options, []string) (Result, error){"ensure": Publish, "verify": VerifyAll} {
		result, err := run(opts, []string{"devin"})
		if err != nil {
			t.Fatal(err)
		}
		state := devinCascadeStateOf(t, result.States)
		if !result.Complete() || len(state.Conflicts) != 0 || state.Route != RouteUnsupported {
			t.Fatalf("%s: complete=%v state=%+v", label, result.Complete(), state)
		}
		if !strings.Contains(strings.Join(state.Details, " "), "not administrator-controlled") {
			t.Fatalf("%s: the untrusted file is not noted: %v", label, state.Details)
		}
	}
	if data, _ := os.ReadFile(legacy); string(data) != adminCascadeHooks {
		t.Fatalf("an untrusted file was edited: %s", data)
	}
}

// An untrusted file that is valid JSON and still holds the earlier refusal,
// but is too large for DefenseClaw to read, cannot be proved clean: verify
// and ensure must report a conflict and leave the file alone, whatever made
// the second read fail.
func TestDevinCascadeReportsAnUntrustedFileItCannotRead(t *testing.T) {
	opts := untrustedCascadeOptions(t)
	legacy, err := devinCascadeLegacyHooksPath(opts)
	if err != nil {
		t.Fatal(err)
	}
	padded := earlierReleaseCascadeFile(t, opts, legacy, `{"note":"`+strings.Repeat("x", policyFileLimit+1)+`"}`)
	writeUntrustedCascadeFile(t, legacy, padded)
	for label, run := range map[string]func(Options, []string) (Result, error){"ensure": Publish, "verify": VerifyAll} {
		result, err := run(opts, []string{"devin"})
		if err != nil {
			t.Fatal(err)
		}
		state := devinCascadeStateOf(t, result.States)
		if result.Complete() || state.Covered || len(state.Conflicts) == 0 || !strings.Contains(strings.Join(state.Conflicts, " "), "cannot read it") {
			t.Fatalf("%s passed a file it could not inspect: complete=%v state=%+v", label, result.Complete(), state)
		}
	}
	if data, _ := os.ReadFile(legacy); string(data) != padded {
		t.Fatal("an untrusted file was edited")
	}
}
