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
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/vault"
)

// stuckKeys is a keystore that never answers until the test ends.
type stuckKeys struct {
	release chan struct{}
	saves   atomic.Int32
}

func newStuckKeys(t *testing.T) *stuckKeys {
	k := &stuckKeys{release: make(chan struct{})}
	t.Cleanup(func() { close(k.release) })
	return k
}

func (k *stuckKeys) Name() string { return "macOS Keychain" }
func (k *stuckKeys) ID() string   { return "macos-keychain" }
func (k *stuckKeys) Load(string) ([]byte, error) {
	<-k.release
	return nil, nil
}
func (k *stuckKeys) Save(string, []byte) error {
	k.saves.Add(1)
	<-k.release
	return nil
}
func (k *stuckKeys) Delete(string) { <-k.release }

func shortSealWait(t *testing.T, d time.Duration) {
	t.Helper()
	prev := vaultSealWait
	vaultSealWait = d
	t.Cleanup(func() { vaultSealWait = prev })
}

// damageVault writes a vault DefenseClaw refuses to read.
func damageVault(t *testing.T, ta *testApp) {
	t.Helper()
	dir := ta.VaultDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, vault.FileName), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
}

// sealRefused: the command failed because the vault could not be sealed.
func sealRefused(err error) bool {
	return err != nil && strings.Contains(err.Error(), "the sandbox vault was not sealed") && strings.Contains(err.Error(), "not valid")
}

// `sandbox run` does not wait on a keystore that does not answer more than
// the short seal wait: the vault stays a file and the run goes on.
func TestRunSealDoesNotWaitOnTheKeystore(t *testing.T) {
	t.Setenv(vault.EnvStore, "")
	const wait = 300 * time.Millisecond
	shortSealWait(t, wait)
	keys := newStuckKeys(t)
	useKeys(t, keys)
	ta := newTestApp(t, "")
	noChanges(ta)
	start := time.Now()
	ta.ok(t, ta.Run(bg, RunOptions{Harness: "claude"}))
	if took := time.Since(start); took > wait+3*time.Second {
		t.Fatalf("the run waited %s on a keystore that does not answer (seal wait %s)", took, wait)
	}
	if n := keys.saves.Load(); n != 1 {
		t.Fatalf("keystore saves = %d", n)
	}
	has(t, ta.output()+ta.err.String(), "not encrypted", "did not answer within 300ms")
	_ = createRequest(t, ta.daemon)
}

// `sandbox start` and a `connect` that starts a stopped sandbox seal the
// vault before the sandbox starts.
func TestStartAndConnectSealVault(t *testing.T) {
	t.Setenv(vault.EnvStore, "")
	ta := newTestApp(t, "", copySandbox("copybox"))
	useKeys(t, &memKeys{items: map[string][]byte{}})
	ta.ok(t, ta.Start(bg, "copybox", StartOptions{}))
	has(t, ta.output()+ta.err.String(), "now sealed")
	if s, err := vault.Open(ta.VaultDir()).Storage(); err != nil || s.Mode != "sealed" {
		t.Fatalf("storage after start = %+v %v", s, err)
	}

	ta = newTestApp(t, "", copySandbox("copybox"))
	ta.daemon.edit("copybox", func(sb *sandboxapi.Sandbox) { sb.Phase = "stopped" })
	_ = ta.Connect(bg, ConnectOptions{Name: "copybox", Prompt: "hello"})
	has(t, ta.output()+ta.err.String(), "now sealed")
	if s, err := vault.Open(ta.VaultDir()).Storage(); err != nil || s.Mode != "sealed" {
		t.Fatalf("storage after connect = %+v %v", s, err)
	}
}

// With DEFENSECLAW_VAULT_STORE=keychain any failure to seal (here a damaged
// vault) fails run, start, a connect that starts a sandbox, and setup;
// without it the failure is a warning.
func TestKeychainSealFailureFailsTheCommand(t *testing.T) {
	t.Setenv(vault.EnvStore, "keychain")
	ta := newTestApp(t, "")
	noChanges(ta)
	damageVault(t, ta)
	if err := ta.Run(bg, RunOptions{Harness: "claude"}); !sealRefused(err) {
		t.Fatalf("keychain run with a damaged vault = %v", err)
	}
	if calls := ta.daemon.callsTo("POST", sandboxapi.PathSandboxes); len(calls) != 0 {
		t.Fatal("a run that could not seal created a sandbox")
	}

	ta = newTestApp(t, "", copySandbox("copybox"))
	damageVault(t, ta)
	if err := ta.Start(bg, "copybox", StartOptions{}); !sealRefused(err) {
		t.Fatalf("keychain start with a damaged vault = %v", err)
	}
	ta.wantCalls(t, 0, "POST", "copybox/start")

	ta = newTestApp(t, "", copySandbox("copybox"))
	ta.daemon.edit("copybox", func(sb *sandboxapi.Sandbox) { sb.Phase = "stopped" })
	damageVault(t, ta)
	if err := ta.Connect(bg, ConnectOptions{Name: "copybox", Prompt: "hello"}); !sealRefused(err) {
		t.Fatalf("keychain connect with a damaged vault = %v", err)
	}
	ta.wantCalls(t, 0, "POST", "copybox/start")

	ta = newTestApp(t, "")
	damageVault(t, ta)
	if err := ta.setupSealVault(); !sealRefused(err) {
		t.Fatalf("keychain setup with a damaged vault = %v", err)
	}

	t.Setenv(vault.EnvStore, "auto")
	ta = newTestApp(t, "", copySandbox("copybox"))
	damageVault(t, ta)
	ta.ok(t, ta.Start(bg, "copybox", StartOptions{}))
	has(t, ta.output()+ta.err.String(), "the sandbox vault was not sealed")
	ta.wantCalls(t, 1, "POST", "copybox/start")
}

// A storage setting that cannot be honoured fails setup as it fails a run.
func TestSetupFailsOnAStoreSetting(t *testing.T) {
	prev := openVault
	openVault = vault.OpenWithKeystore
	t.Cleanup(func() { openVault = prev })
	t.Setenv(vault.EnvStore, "sealed-please")
	ta := newTestApp(t, "")
	if err := ta.setupSealVault(); !errors.Is(err, vault.ErrStoreSetting) {
		t.Fatalf("setup with an unknown storage setting = %v", err)
	}
	if err := ta.sealVault(); !errors.Is(err, vault.ErrStoreSetting) {
		t.Fatalf("run seal with an unknown storage setting = %v", err)
	}
}
