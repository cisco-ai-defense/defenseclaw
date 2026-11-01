// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisebundle"
	"github.com/defenseclaw/defenseclaw/internal/enterpriseunix"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// noServiceAccount is a device before the first install: no service
// account, so a credential is written root-only.
type noServiceAccount struct{}

func (noServiceAccount) Lookup(context.Context, string) (enterpriseunix.Account, bool, error) {
	return enterpriseunix.Account{}, false, nil
}
func (noServiceAccount) Ensure(context.Context, string) (enterpriseunix.Account, error) {
	return enterpriseunix.Account{}, errors.New("no accounts in this test")
}
func (noServiceAccount) Remove(context.Context, string) error { return nil }

// GAP-1887, GAP-1888: the change secret set and secret remove make, and the
// put-back the lifecycle runs when the ensure then refuses the config
// (enterpriseunix TestRefusedSecretChangeIsPutBack proves it runs only
// then). A refused set over a stored credential leaves its bytes, a refused
// set of a new credential leaves none, and a refused remove puts the
// removed credential back.
func TestRefusedUnixSecretChangeLeavesTheCredentialStoreAsItWas(t *testing.T) {
	layout, err := managed.StandaloneLayoutFor(enterpriseunix.CurrentGOOS())
	if err != nil {
		t.Skip(err)
	}
	saved := bundleStore
	t.Cleanup(func() { bundleStore = saved })
	dir := t.TempDir()
	store := enterprisebundle.NewStore(filepath.Join(dir, "bundles"), filepath.Join(dir, "lifecycle"))
	bundleStore = func() (*enterprisebundle.Store, error) { return store, nil }
	const name = "galileo-api-key"
	for _, tc := range []struct {
		test, action string
		before       []byte // nil: not stored
		value        []byte
		changed      []byte // nil: absent after the change
	}{
		{"set over a stored credential", "set", []byte("old-value"), []byte("new-value"), []byte("new-value")},
		{"set of a new credential", "set", nil, []byte("new-value"), []byte("new-value")},
		{"remove of a stored credential", "remove", []byte("old-value"), nil, nil},
	} {
		t.Run(tc.test, func(t *testing.T) {
			env := &enterpriseunix.Env{GOOS: enterpriseunix.CurrentGOOS(), Root: t.TempDir(), Layout: layout, Accounts: noServiceAccount{},
				Lchown: func(string, int, int) error { return nil }, Fchown: func(*os.File, int, int) error { return nil }}
			path := filepath.Join(env.P(layout.SecretsDir), name)
			if tc.before != nil {
				if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, tc.before, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			read := func() []byte {
				got, err := os.ReadFile(path)
				if errors.Is(err, os.ErrNotExist) {
					return nil
				}
				if err != nil {
					t.Fatal(err)
				}
				return got
			}
			change := &unixSecretChange{env: env, action: tc.action, opts: &enterpriseSecretOptions{name: name}, value: tc.value, caller: secretCallerPID()}
			if err := change.mutate(t.Context()); err != nil {
				t.Fatalf("%s: %v", tc.action, err)
			}
			if got := read(); string(got) != string(tc.changed) || (got == nil) != (tc.changed == nil) {
				t.Fatalf("after the %s the credential holds %q, want %q", tc.action, got, tc.changed)
			}
			if err := change.putBack(t.Context()); err != nil {
				t.Fatalf("put back: %v", err)
			}
			if got := read(); string(got) != string(tc.before) || (got == nil) != (tc.before == nil) {
				t.Fatalf("after the put-back the credential holds %q, want %q", got, tc.before)
			}
		})
	}
}
