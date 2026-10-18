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
	"errors"
	"io/fs"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// Bundle verify and apply run in a plain SYSTEM or administrator shell: the
// lookup pins the gateway service account from the layout, as the service
// does, and only a credential that is not stored counts as missing; any
// other failure is unchecked, never missing (GAP-0009).
func TestManagedBundleSecretPresentWindows(t *testing.T) {
	layout, err := managed.StandaloneWindowsLayout()
	if err != nil {
		t.Fatal(err)
	}
	previous := resolveBundleSecret
	t.Cleanup(func() { resolveBundleSecret = previous })
	for _, tc := range []struct {
		name    string
		err     error
		present bool
		wantErr bool
	}{
		{"stored", nil, true, false},
		{"not stored", managed.ErrNoServiceCredential, false, false},
		{"access denied", fs.ErrPermission, false, true},
		{"reader check refused", errors.New("principal S-1-5-80-1 may read the protected credential"), false, true},
	} {
		resolveBundleSecret = func(name, dir, account string) ([]byte, managed.CredentialSource, error) {
			if name != "sv2-llm-key" || dir != layout.SecretsDir || account != layout.ServiceUser || account == "" {
				t.Fatalf("resolved %q in %q as %q", name, dir, account)
			}
			if tc.err != nil {
				return nil, "", tc.err
			}
			return []byte("value"), managed.CredentialFromFile, nil
		}
		present, err := managedBundleSecretPresent("sv2-llm-key")
		if present != tc.present || (err != nil) != tc.wantErr {
			t.Errorf("%s: present %v err %v", tc.name, present, err)
		}
	}
}
