// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package sandboxcli

import (
	"errors"
	"io/fs"
	"os"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/vault"
)

func useKeys(t *testing.T, keys vault.Keystore) {
	t.Helper()
	prev := openVault
	openVault = func(dir string) *vault.Store { return vault.OpenWith(dir, keys) }
	t.Cleanup(func() { openVault = prev })
}

// `sandbox run` seals the vault before the sandbox is created, so what the
// gateway captures from it is sealed; without a keystore it writes no vault.
func TestRunSealsVault(t *testing.T) {
	ta := newTestApp(t, "")
	noChanges(ta)
	ta.ok(t, ta.Run(bg, RunOptions{Harness: "claude"}))
	if _, err := os.Stat(vault.Open(ta.VaultDir()).Path()); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("a run without a keystore wrote a vault: %v", err)
	}

	ta = newTestApp(t, "")
	noChanges(ta)
	useKeys(t, &memKeys{items: map[string][]byte{}})
	ta.ok(t, ta.Run(bg, RunOptions{Harness: "claude"}))
	has(t, ta.output()+ta.err.String(), "now sealed", "macOS Keychain")
	_ = createRequest(t, ta.daemon)
	daemon := vault.Open(ta.VaultDir())
	if s, err := daemon.Storage(); err != nil || s.Mode != "sealed" {
		t.Fatalf("storage after run = %+v %v", s, err)
	}
	if _, err := daemon.Capture(vault.CaptureInput{Value: fakeVaultValue(), Kind: "stripe-secret-key", From: "claudecode prompt in sandbox sb"}); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(daemon.Path())
	if err != nil {
		t.Fatal(err)
	}
	lacks(t, string(raw), fakeVaultValue())
}

// `sandbox setup` seals the vault too, and says how it is kept when it
// stays a file.
func TestSetupSealsVault(t *testing.T) {
	ta := newTestApp(t, "")
	ta.setupSealVault()
	has(t, ta.output()+ta.err.String(), "file readable only by you, not encrypted")

	ta = newTestApp(t, "")
	useKeys(t, &memKeys{items: map[string][]byte{}})
	ta.setupSealVault()
	has(t, ta.output()+ta.err.String(), "now sealed")
	if s, err := vault.Open(ta.VaultDir()).Storage(); err != nil || s.Mode != "sealed" {
		t.Fatalf("storage after setup = %+v %v", s, err)
	}
}

// Confirming a captured secret needs no key: without one the last
// characters are not shown and the confirmation still lands.
func TestVaultConfirmWithoutKey(t *testing.T) {
	ta := newTestApp(t, "")
	keys := &memKeys{items: map[string][]byte{}}
	useKeys(t, keys)
	ta.setupSealVault()
	if _, err := vault.Open(ta.VaultDir()).Capture(vault.CaptureInput{Value: fakeVaultValue(), Kind: "stripe-secret-key", From: "claudecode prompt in sandbox sb"}); err != nil {
		t.Fatal(err)
	}
	useKeys(t, nil)
	ta.out.Reset()
	ta.ok(t, ta.VaultConfirm("STRIPE_API_KEY", true))
	has(t, ta.output(), "Ends with", "(not readable without the key)", "confirmed STRIPE_API_KEY")
	lacks(t, ta.output(), fakeVaultValue()[len(fakeVaultValue())-4:])
	e, err := vault.Open(ta.VaultDir()).Get("STRIPE_API_KEY")
	if err != nil || !e.Confirmed {
		t.Fatalf("confirmed = %+v %v", e, err)
	}
	if _, v, err := vault.OpenWith(ta.VaultDir(), keys).Resolve("STRIPE_API_KEY"); err != nil || v != fakeVaultValue() {
		t.Fatalf("resolve with the key = %v", err)
	}
}
