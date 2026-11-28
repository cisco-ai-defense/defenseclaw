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
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func mustNotExist(t *testing.T, s *Store) {
	t.Helper()
	if _, err := os.Stat(s.Path()); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("a vault was written: %v", err)
	}
}

// Seal makes an empty sealed vault where there is none, so what the daemon
// captures afterwards is sealed; it leaves a sealed vault and the keystore
// alone; it writes nothing without a keystore, and says why a keystore that
// cannot keep the key leaves the vault a file.
func TestVaultSealNowBeforeCapture(t *testing.T) {
	ks := newFakeKeys()
	cli := sealedStore(t, ks)
	if err := cli.Seal(); err != nil {
		t.Fatal(err)
	}
	if n := cli.Notice(); !strings.Contains(n, "now sealed") {
		t.Fatalf("notice = %q", n)
	}
	if fileVersionOf(t, rawVault(t, cli)) != sealedVersion {
		t.Fatal("the vault was not sealed")
	}
	calls, _ := ks.count()
	if err := cli.Seal(); err != nil || cli.Notice() != "" {
		t.Fatalf("second seal = %v", err)
	}
	if c, _ := ks.count(); c != calls {
		t.Fatal("sealing a sealed vault called the keystore")
	}
	daemon := withClock(Open(cli.Dir()))
	if _, err := daemon.CaptureAll([]CaptureInput{{Value: fakeGitHub(), Kind: "github-token"}}, CaptureWait); err != nil {
		t.Fatal(err)
	}
	raw := rawVault(t, cli)
	mustNotHold(t, raw, fakeGitHub())
	if fileVersionOf(t, raw) != sealedVersion {
		t.Fatal("the capture unsealed the vault")
	}
	if c, _ := ks.count(); c != calls {
		t.Fatal("the capture called the keystore")
	}

	none := OpenWith(filepath.Join(t.TempDir(), "vault"), nil)
	if err := none.Seal(); err != nil || none.Notice() != "" {
		t.Fatalf("no keystore = %v", err)
	}
	mustNotExist(t, none)

	bad := newFakeKeys()
	bad.saveErr = errors.New("the macOS keychain is locked")
	failing := OpenWith(filepath.Join(t.TempDir(), "vault"), bad)
	if err := failing.Seal(); err != nil {
		t.Fatal(err)
	}
	if n := failing.Notice(); !strings.Contains(n, "not encrypted") || !strings.Contains(n, "locked") {
		t.Fatalf("notice = %q", n)
	}
	mustNotExist(t, failing)

	d := Open(filepath.Join(t.TempDir(), "vault"))
	if err := d.Seal(); err != nil {
		t.Fatal(err)
	}
	mustNotExist(t, d)
}

// Seal migrates a file vault with its values, leaving none in the clear.
func TestVaultSealNowMigrates(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "vault")
	if _, err := withClock(OpenWith(dir, nil)).Add(AddInput{Name: "A", Value: "value-a", Host: "api.example.com"}); err != nil {
		t.Fatal(err)
	}
	ks := newFakeKeys()
	cli := withClock(OpenWith(dir, ks))
	if err := cli.Seal(); err != nil {
		t.Fatal(err)
	}
	raw := rawVault(t, cli)
	mustNotHold(t, raw, "value-a")
	if fileVersionOf(t, raw) != sealedVersion {
		t.Fatal("not sealed")
	}
	if _, v, err := OpenWith(dir, ks).Resolve("A"); err != nil || v != "value-a" {
		t.Fatalf("resolve = %v", err)
	}
}

// DEFENSECLAW_VAULT_STORE=keychain is strict: a change (or Seal) that
// cannot seal fails and writes nothing; auto never is.
func TestVaultSealKeychainStrict(t *testing.T) {
	bad := newFakeKeys()
	bad.saveErr = errors.New("the macOS keychain is locked")
	s := sealedStore(t, required{bad})
	_, err := s.Add(AddInput{Name: "A", Value: "value-a", Host: "api.example.com"})
	if !errors.Is(err, ErrStoreSetting) || !strings.Contains(err.Error(), EnvStore+"=keychain") || !strings.Contains(err.Error(), "locked") {
		t.Fatalf("strict add = %v", err)
	}
	mustNotExist(t, s)
	if err := s.Seal(); !errors.Is(err, ErrStoreSetting) {
		t.Fatalf("strict seal = %v", err)
	}
	mustNotExist(t, s)

	t.Setenv(EnvStore, "keychain")
	ks, _, err := keysFromEnv()
	if osKs, _, _ := osKeystore(); osKs == nil {
		if !errors.Is(err, ErrStoreSetting) || !strings.Contains(err.Error(), "keychain") {
			t.Fatalf("keychain without a keystore = %v", err)
		}
		if _, err := OpenWithKeystore(filepath.Join(t.TempDir(), "vault")).Add(AddInput{Name: "A", Value: "value-a"}); !errors.Is(err, ErrStoreSetting) {
			t.Fatalf("keychain without a keystore wrote a file: %v", err)
		}
	} else if err != nil || !isRequired(ks) {
		t.Fatalf("keychain = %v %v", ks, err)
	}
	t.Setenv(EnvStore, "auto")
	if ks, _, _ := keysFromEnv(); ks != nil && isRequired(ks) {
		t.Fatal("auto is strict")
	}
}

// A sealed vault seen from a session that does not read its key says that
// value-changing commands fail there.
func TestVaultSealStorageWithoutKey(t *testing.T) {
	ks := newFakeKeys()
	s := sealedStore(t, ks)
	if _, err := s.Add(AddInput{Name: "A", Value: "value-a", Host: "api.example.com"}); err != nil {
		t.Fatal(err)
	}
	st, err := OpenWith(s.Dir(), nil).Storage()
	if err != nil || st.Mode != "sealed" || !strings.Contains(st.Note, "does not read the vault key") || !strings.Contains(st.Note, "fail") {
		t.Fatalf("storage = %+v %v", st, err)
	}
	if st, _ := s.Storage(); st.Note != "" {
		t.Fatalf("storage with the key = %+v", st)
	}
}
