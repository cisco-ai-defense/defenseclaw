// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"fmt"
	"io/fs"
	"syscall"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// Bundle verify and apply run in a plain SYSTEM or administrator shell: the
// lookup pins the gateway service account from the layout, as the service
// does (GAP-0009). A credential that is not stored, or that is stored but
// the gateway's read refuses (an extra reader ACE, empty, too large), is
// missing, so a required reference refuses; only a store the caller cannot
// read is unchecked. Each reference is classified on its own. The
// classification of the real check errors is pinned on every OS by
// managed.TestStoredCredentialValue.
func TestManagedBundleSecretValueWindows(t *testing.T) {
	layout, err := managed.StandaloneWindowsLayout()
	if err != nil {
		t.Fatal(err)
	}
	unusable := func(detail string) error {
		return fmt.Errorf("%s: %w", detail, managed.ErrUnusableServiceCredential)
	}
	store := map[string]error{
		"sv2-llm-key":      nil,
		"not-stored":       managed.ErrNoServiceCredential,
		"extra-reader":     unusable(`principal S-1-5-32-545 may read the protected credential; only LocalSystem, Administrators and the gateway service may`),
		"empty":            unusable("credential empty: credential is empty"),
		"oversized":        unusable(fmt.Sprintf("credential oversized: credential exceeds %d bytes", managed.ServiceCredentialLimit)),
		"denied":           fs.ErrPermission,
		"unreadable-store": fmt.Errorf("inspect credential unreadable-store: %w", &fs.PathError{Op: "lstat", Err: syscall.ERROR_ACCESS_DENIED}),
		"descriptor":       fmt.Errorf("inspect Windows security descriptor: %w", syscall.ERROR_ACCESS_DENIED),
	}
	previous := resolveBundleSecret
	t.Cleanup(func() { resolveBundleSecret = previous })
	resolveBundleSecret = func(name, dir, account string) ([]byte, managed.CredentialSource, error) {
		if dir != layout.SecretsDir || account != layout.ServiceUser || account == "" {
			t.Fatalf("resolved %q in %q as %q", name, dir, account)
		}
		err, ok := store[name]
		if !ok {
			t.Fatalf("unexpected lookup %q", name)
		}
		if err != nil {
			return nil, "", err
		}
		return []byte("value"), managed.CredentialFromFile, nil
	}
	for _, tc := range []struct {
		name      string
		present   bool
		unchecked bool
	}{
		{"sv2-llm-key", true, false},
		{"not-stored", false, false},
		{"extra-reader", false, false},
		{"empty", false, false},
		{"oversized", false, false},
		{"denied", false, true},
		{"unreadable-store", false, true},
		{"descriptor", false, true},
	} {
		value, err := managedBundleSecretValue(tc.name)
		if (value != nil) != tc.present || (err != nil) != tc.unchecked {
			t.Errorf("%s: value %v err %v", tc.name, value != nil, err)
		}
	}
	// Two references, one unusable and one fine: each keeps its own result.
	for _, pair := range [][2]string{{"extra-reader", "sv2-llm-key"}, {"sv2-llm-key", "empty"}} {
		got := map[string]bool{}
		for _, name := range pair {
			value, err := managedBundleSecretValue(name)
			if err != nil {
				t.Fatalf("%v: %s unchecked: %v", pair, name, err)
			}
			got[name] = value != nil
		}
		if !got["sv2-llm-key"] || got[pair[0]] == got[pair[1]] {
			t.Errorf("%v: presence %v", pair, got)
		}
	}
}
