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

package vault

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/keystore"
)

// stuckKeys is a keystore that never answers until released.
type stuckKeys struct {
	release chan struct{}
}

func newStuckKeys(t *testing.T) *stuckKeys {
	k := &stuckKeys{release: make(chan struct{})}
	t.Cleanup(func() { close(k.release) })
	return k
}

func (k *stuckKeys) Name() string { return keystoreName(keystoreMac) }
func (k *stuckKeys) ID() string   { return keystoreMac }
func (k *stuckKeys) Load(string) ([]byte, error) {
	<-k.release
	return nil, nil
}
func (k *stuckKeys) Save(string, []byte) error {
	<-k.release
	return nil
}
func (k *stuckKeys) Delete(string) { <-k.release }

// A seal on the way to a sandbox gives a keystore that does not answer the
// short wait only: the vault stays a file and the command goes on.
func TestVaultBrieflyBoundsTheKeystore(t *testing.T) {
	t.Setenv(EnvStore, "")
	s := OpenWith(filepath.Join(t.TempDir(), "vault"), newStuckKeys(t)).Briefly(100 * time.Millisecond)
	start := time.Now()
	if err := s.Seal(); err != nil {
		t.Fatal(err)
	}
	if took := time.Since(start); took > time.Second {
		t.Fatalf("the seal waited %s on a keystore that does not answer", took)
	}
	if n := s.Notice(); !strings.Contains(n, "not encrypted") || !strings.Contains(n, "did not answer within 100ms") {
		t.Fatalf("notice = %q", n)
	}
	mustNotExist(t, s)

	// A keystore that answers seals as before.
	ks := newFakeKeys()
	ok := sealedStore(t, ks).Briefly(time.Second)
	if err := ok.Seal(); err != nil || !strings.Contains(ok.Notice(), "now sealed") {
		t.Fatalf("brief seal = %v", err)
	}
	if fileVersionOf(t, rawVault(t, ok)) != sealedVersion {
		t.Fatal("the vault was not sealed")
	}
}

// On the way to a sandbox, the Secret Service is not tried from a session
// that names no D-Bus session bus; a vault change still tries it.
func TestVaultBrieflySkipsSecretServiceWithoutBus(t *testing.T) {
	t.Setenv(EnvStore, "")
	t.Setenv("DBUS_SESSION_BUS_ADDRESS", "")
	ks := newFakeKeys()
	ks.id = keystoreSecretService
	s := sealedStore(t, ks)
	if err := s.Briefly(time.Second).Seal(); err != nil {
		t.Fatal(err)
	}
	if calls, _ := ks.count(); calls != 0 {
		t.Fatalf("the Secret Service was called %d times without a session bus", calls)
	}
	mustNotExist(t, s)

	t.Setenv("DBUS_SESSION_BUS_ADDRESS", "unix:path=/run/user/1000/bus")
	if err := s.Briefly(time.Second).Seal(); err != nil {
		t.Fatal(err)
	}
	if fileVersionOf(t, rawVault(t, s)) != sealedVersion {
		t.Fatal("the vault was not sealed with a session bus")
	}
}

// DEFENSECLAW_VAULT_STORE=keychain asks for a sealed vault: the seal on the
// way to a sandbox then waits for the keystore as a vault change does.
func TestVaultBrieflyKeychainWaits(t *testing.T) {
	s := sealedStore(t, newFakeKeys())
	t.Setenv(EnvStore, "keychain")
	if s.Briefly(time.Second) != s {
		t.Fatal("keychain mode bounded the keystore")
	}
	t.Setenv(EnvStore, " Keychain ")
	if !Required() {
		t.Fatal("Required ignores case and spaces")
	}
	t.Setenv(EnvStore, "auto")
	if Required() || s.Briefly(time.Second) == s {
		t.Fatal("auto is strict")
	}
}

// A bounded Secret Service ends secret-tool at the bound.
func TestVaultKeysSecretServiceWithin(t *testing.T) {
	run := func(ctx context.Context, _ []byte, _ string, _ ...string) ([]byte, string, int, error) {
		<-ctx.Done()
		return nil, "", 0, ctx.Err()
	}
	s := secretService{t: keystore.SecretTool{Run: run, Bin: "secret-tool"}}
	b := boundKeys(s, 50*time.Millisecond).(bounded)
	if got := b.Keystore.(secretService).limit(); got != 50*time.Millisecond {
		t.Fatalf("secret-tool bound = %s", got)
	}
	start := time.Now()
	err := b.Save("0123456789abcdef0123456789abcdef", testKey())
	if err == nil || !strings.Contains(err.Error(), "50ms") {
		t.Fatalf("save = %v", err)
	}
	if took := time.Since(start); took > time.Second {
		t.Fatalf("save took %s", took)
	}
	if s.limit() != keyTimeout {
		t.Fatal("an unbounded Secret Service lost its timeout")
	}
}
