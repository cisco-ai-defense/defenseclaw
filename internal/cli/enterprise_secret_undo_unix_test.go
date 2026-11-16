// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisebundle"
	"github.com/defenseclaw/defenseclaw/internal/enterpriseunix"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

type unixSecretTestAccount struct{}

func (unixSecretTestAccount) Lookup(_ context.Context, name string) (enterpriseunix.Account, bool, error) {
	return enterpriseunix.Account{Name: name, UID: 1001, GID: 1001}, true, nil
}

func (unixSecretTestAccount) Ensure(_ context.Context, name string) (enterpriseunix.Account, error) {
	return enterpriseunix.Account{Name: name, UID: 1001, GID: 1001}, nil
}

func (unixSecretTestAccount) Remove(context.Context, string) error { return nil }

// GAP-1173: the installed config references credential ai-key with no value
// stored, and a failed rotation added the value. The put-back (remove
// --undo-rotation --undo-config) removes it while that very config is
// installed; a config installed since keeps it (credential_in_use), and a
// plain remove still refuses a referenced credential.
func TestUnixPutBackRemovesTheCredentialAFailedRotationAdded(t *testing.T) {
	layout, err := managed.StandaloneLayoutFor(enterpriseunix.CurrentGOOS())
	if err != nil {
		t.Skip(err)
	}
	saved := bundleStore
	t.Cleanup(func() { bundleStore = saved })
	dir := t.TempDir()
	store := enterprisebundle.NewStore(filepath.Join(dir, "bundles"), filepath.Join(dir, "lifecycle"))
	bundleStore = func() (*enterprisebundle.Store, error) { return store, nil }
	before := []byte("config_version: 8\nenterprise:\n  profile: standalone\n  inspection:\n    ai_defense:\n      enabled: true\n      credential: ai-key\n")
	sum := func(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }
	const value = "new-key"
	for _, tc := range []struct {
		name      string
		installed []byte
		opts      enterpriseSecretOptions
		removed   bool
		code      string
	}{
		{"put-back on the config from before", before,
			enterpriseSecretOptions{undoRotation: "none", undoConfig: sum(before), ifStored: sum([]byte(value))}, true, ""},
		{"put-back on a config installed since", append(append([]byte{}, before...), "# since\n"...),
			enterpriseSecretOptions{undoRotation: "none", undoConfig: sum(before), ifStored: sum([]byte(value))}, false, "credential_in_use"},
		{"plain remove of a referenced credential", before, enterpriseSecretOptions{}, false, ""},
		{"plain remove without config", nil, enterpriseSecretOptions{}, false, "state_invalid"},
		{"put-back without config from a prior config", nil,
			enterpriseSecretOptions{undoRotation: "none", undoConfig: sum(before), ifStored: sum([]byte(value))}, false, "state_invalid"},
		{"put-back without config when none was installed before", nil,
			enterpriseSecretOptions{undoRotation: "none", undoConfig: "none", ifStored: sum([]byte(value))}, true, ""},
		{"put-back on malformed config", []byte("guardrail: [\n"),
			enterpriseSecretOptions{undoRotation: "none", undoConfig: "none", ifStored: sum([]byte(value))}, false, "state_invalid"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			env := &enterpriseunix.Env{GOOS: enterpriseunix.CurrentGOOS(), Root: root, Layout: layout,
				Trust:    func(string, enterpriseunix.TrustKind) error { return nil },
				Accounts: unixSecretTestAccount{},
				OwnerOf:  func(string) (int, int, error) { return 1001, 1001, nil }}
			files := map[string][]byte{
				filepath.Join(env.P(layout.SecretsDir), "ai-key"): []byte(value),
			}
			if tc.installed != nil {
				files[env.P(layout.ConfigPath)] = tc.installed
			}
			for path, data := range files {
				if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, data, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			opts := tc.opts
			opts.name = "ai-key"
			err := removeUnixSecret(env, &opts)
			_, statErr := os.Stat(filepath.Join(env.P(layout.SecretsDir), "ai-key"))
			if removed := os.IsNotExist(statErr); removed != tc.removed {
				t.Fatalf("removed = %v (err %v), want %v", removed, err, tc.removed)
			}
			if tc.removed && err != nil {
				t.Fatalf("put-back: %v", err)
			}
			if !tc.removed && err == nil {
				t.Fatal("a referenced credential was kept without a refusal")
			}
			if tc.code != "" && string(enterprisebundle.CodeOf(err)) != tc.code {
				t.Fatalf("code = %q (%v), want %s", enterprisebundle.CodeOf(err), err, tc.code)
			}
		})
	}
}
