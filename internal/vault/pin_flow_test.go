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
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func capture(s *Store) error {
	_, err := Open(s.Dir()).CaptureAll([]CaptureInput{{Value: fakeGitHub(), Kind: "github-token"}}, time.Second)
	return err
}

func mustPin(t *testing.T, s *Store, by string) *pinRecord {
	t.Helper()
	p, err := s.readPin()
	if err != nil || p == nil {
		t.Fatalf("pin = %v, %v", p, err)
	}
	if p.By != by {
		t.Fatalf("pin by %q, want %q", p.By, by)
	}
	return p
}

func sealedWithA(t *testing.T, ks Keystore) *Store {
	t.Helper()
	s := sealedStore(t, ks)
	if _, err := s.Add(AddInput{Name: "A", Value: "value-a", Host: "api.example.com"}); err != nil {
		t.Fatal(err)
	}
	return s
}

func downgrade(t *testing.T, s *Store) {
	t.Helper()
	if err := os.WriteFile(s.Path(), []byte(`{"version": 1, "entries": []}`), 0o600); err != nil {
		t.Fatal(err)
	}
}

// The CLI that seals the vault pins its header, beside the vault directory.
func TestSealPinsTheHeader(t *testing.T) {
	s := sealedWithA(t, newFakeKeys())
	if filepath.Dir(s.PinPath()) != filepath.Dir(s.Dir()) {
		t.Fatalf("pin %s is not beside the vault directory %s", s.PinPath(), s.Dir())
	}
	f, err := s.read()
	if err != nil {
		t.Fatal(err)
	}
	if p := mustPin(t, s, pinByKey); p.Header != headerDigest(f.sealer.h) || p.KeyID != f.sealer.h.KeyID {
		t.Fatal("the pin is not the vault's header")
	}
	if err := capture(s); err != nil {
		t.Fatalf("a capture into the pinned vault: %v", err)
	}
	if st, err := s.Storage(); err != nil || st.Pin != "" {
		t.Fatalf("storage = %+v, %v", st, err)
	}
}

// A plain vault gets no pin and captures as before.
func TestPlainVaultHasNoPin(t *testing.T) {
	s := sealedStore(t, nil)
	if _, err := s.Add(AddInput{Name: "A", Value: "value-a", Host: "api.example.com"}); err != nil {
		t.Fatal(err)
	}
	if err := capture(s); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(s.PinPath()); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("a plain vault was pinned")
	}
	if st, _ := s.Storage(); st.Pin != "" || st.Mode != "file" {
		t.Fatalf("storage = %+v", st)
	}
}

// A sealed vault with no pin (sealed by an older DefenseClaw) is pinned by
// its first capture; a key read later renews the pin as checked.
func TestFirstCapturePinsAndKeyConfirms(t *testing.T) {
	ks := newFakeKeys()
	s := sealedWithA(t, ks)
	if err := os.Remove(s.PinPath()); err != nil {
		t.Fatal(err)
	}
	if st, _ := s.Storage(); st.Pin != "not pinned yet" {
		t.Fatalf("storage = %+v", st)
	}
	if err := capture(s); err != nil {
		t.Fatal(err)
	}
	mustPin(t, s, pinByFirstUse)
	if _, _, err := OpenWith(s.Dir(), ks).Resolve("A"); err != nil {
		t.Fatal(err)
	}
	mustPin(t, s, pinByKey)
	swapHeader(t, s)
	if err := capture(s); !errors.Is(err, ErrSealChanged) {
		t.Fatalf("err = %v, want ErrSealChanged", err)
	}
}

// A damaged or rewritten pin refuses the capture; `vault list` checks the
// vault with the key, pins it again, and captures work.
func TestVaultListRepinsAGenuineVault(t *testing.T) {
	for name, pin := range map[string][]byte{
		"damaged":   []byte("not a pin"),
		"rewritten": nil,
	} {
		t.Run(name, func(t *testing.T) {
			ks := newFakeKeys()
			s := sealedWithA(t, ks)
			if pin == nil {
				b, err := os.ReadFile(s.PinPath())
				if err != nil {
					t.Fatal(err)
				}
				f, _ := s.read()
				pin = bytes.Replace(b, []byte(headerDigest(f.sealer.h)), []byte(strings.Repeat("0", 64)), 1)
			}
			if err := os.WriteFile(s.PinPath(), pin, 0o600); err != nil {
				t.Fatal(err)
			}
			before := rawVault(t, s)
			if err := capture(s); !errors.Is(err, ErrSealChanged) {
				t.Fatalf("err = %v, want ErrSealChanged", err)
			}
			if !bytes.Equal(before, rawVault(t, s)) {
				t.Fatal("a refused capture changed the vault")
			}
			if st, _ := s.Storage(); st.Pin != "changed" || !strings.Contains(st.Note, "capture nothing") {
				t.Fatalf("storage = %+v", st)
			}
			note, err := OpenWith(s.Dir(), ks).CheckPin()
			if err != nil || !strings.Contains(note, "pinned again") {
				t.Fatalf("check = %q, %v", note, err)
			}
			mustPin(t, s, pinByKey)
			if err := capture(s); err != nil {
				t.Fatal(err)
			}
			mustNotHold(t, rawVault(t, s), fakeGitHub())
		})
	}
}

// `vault list` after a header swap: the key does not match, so nothing is
// pinned again and captures stay off.
func TestVaultListKeepsASwappedVaultRefused(t *testing.T) {
	ks := newFakeKeys()
	s := sealedWithA(t, ks)
	pinBefore, err := os.ReadFile(s.PinPath())
	if err != nil {
		t.Fatal(err)
	}
	swapHeader(t, s)
	if st, _ := s.Storage(); st.Pin != "changed" {
		t.Fatalf("storage = %+v", st)
	}
	note, err := OpenWith(s.Dir(), ks).CheckPin()
	if err == nil || note != "" || !strings.Contains(err.Error(), "the file was changed") {
		t.Fatalf("check = %q, %v", note, err)
	}
	if after, _ := os.ReadFile(s.PinPath()); !bytes.Equal(pinBefore, after) {
		t.Fatal("a swapped header was pinned")
	}
	// Without a key the check cannot tell, and pins nothing.
	if _, err := OpenWith(s.Dir(), nil).CheckPin(); err == nil || !strings.Contains(err.Error(), "cannot check it") {
		t.Fatalf("check without key: %v", err)
	}
	if err := capture(s); !errors.Is(err, ErrSealChanged) {
		t.Fatalf("err = %v, want ErrSealChanged", err)
	}
	// A CLI change that reads no key is refused too; one that needs the
	// values finds the key does not match.
	if err := OpenWith(s.Dir(), nil).Remove("A"); !errors.Is(err, ErrSealChanged) {
		t.Fatalf("remove = %v, want ErrSealChanged", err)
	}
	if _, err := OpenWith(s.Dir(), ks).Add(AddInput{Name: "B", Value: "value-b", Host: "api.example.com"}); !errors.Is(err, ErrDamaged) {
		t.Fatalf("add = %v, want ErrDamaged", err)
	}
}

// `vault list` after a downgrade seals the vault again with a new key, and
// captures are sealed again.
func TestVaultListSealsADowngradedVaultAgain(t *testing.T) {
	ks := newFakeKeys()
	s := sealedWithA(t, ks)
	downgrade(t, s)
	if st, _ := s.Storage(); st.Pin != "unsealed" || st.Mode != "file" {
		t.Fatalf("storage = %+v", st)
	}
	note, err := OpenWith(s.Dir(), ks).CheckPin()
	if err != nil || !strings.Contains(note, "sealed again") {
		t.Fatalf("check = %q, %v", note, err)
	}
	mustPin(t, s, pinByKey)
	if err := capture(s); err != nil {
		t.Fatal(err)
	}
	raw := rawVault(t, s)
	mustNotHold(t, raw, fakeGitHub())
	if !bytes.Contains(raw, []byte(`"version": 2`)) {
		t.Fatal("the vault is not sealed again")
	}
}

// Without a keystore a downgraded vault stays refused, for the gateway and
// for a CLI change; DEFENSECLAW_VAULT_STORE=file is the explicit way to
// keep a plain vault.
func TestDowngradedVaultWithoutKeystore(t *testing.T) {
	s := sealedWithA(t, newFakeKeys())
	downgrade(t, s)
	if _, err := OpenWith(s.Dir(), nil).CheckPin(); err == nil || !strings.Contains(err.Error(), EnvStore+"=file") {
		t.Fatalf("check without keystore: %v", err)
	}
	if _, err := OpenWith(s.Dir(), nil).Add(AddInput{Name: "B", Value: "value-b", Host: "api.example.com"}); !errors.Is(err, ErrSealRemoved) {
		t.Fatalf("add = %v, want ErrSealRemoved", err)
	}
	mustNotHold(t, rawVault(t, s), "value-b")
	if err := capture(s); !errors.Is(err, ErrSealRemoved) {
		t.Fatalf("err = %v, want ErrSealRemoved", err)
	}
	t.Setenv(EnvStore, "file")
	note, err := OpenWithKeystore(s.Dir()).CheckPin()
	if err != nil || !strings.Contains(note, EnvStore+"=file") {
		t.Fatalf("check with file mode = %q, %v", note, err)
	}
	if _, err := os.Stat(s.PinPath()); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("the pin was kept after the person chose a plain vault")
	}
	if err := capture(s); err != nil {
		t.Fatal(err)
	}
}

func rewriteHeader(t *testing.T, s *Store, field, value string) {
	t.Helper()
	var f map[string]any
	if err := json.Unmarshal(rawVault(t, s), &f); err != nil {
		t.Fatal(err)
	}
	f["seal"].(map[string]any)[field] = value
	b, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(s.Path(), b, 0o600); err != nil {
		t.Fatal(err)
	}
}

// A swapped fingerprint salt is caught: captures are refused, and `vault
// list` finds the fingerprints do not match and pins nothing.
func TestVaultListRefusesASwappedSalt(t *testing.T) {
	ks := newFakeKeys()
	s := sealedWithA(t, ks)
	if err := capture(s); err != nil {
		t.Fatal(err)
	}
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		t.Fatal(err)
	}
	pinBefore, _ := os.ReadFile(s.PinPath())
	rewriteHeader(t, s, "fp_salt", base64.StdEncoding.EncodeToString(salt))
	if err := capture(s); !errors.Is(err, ErrSealChanged) {
		t.Fatalf("err = %v, want ErrSealChanged", err)
	}
	if _, err := OpenWith(s.Dir(), ks).CheckPin(); err == nil || !strings.Contains(err.Error(), "fingerprint salt") {
		t.Fatalf("check = %v", err)
	}
	if after, _ := os.ReadFile(s.PinPath()); !bytes.Equal(pinBefore, after) {
		t.Fatal("a swapped salt was pinned")
	}
}

// A CLI change that reads the key does not replace a pin that differs from
// the header: only `vault list` does, after checking every value.
func TestKeyedChangeLeavesADifferingPinToVaultList(t *testing.T) {
	ks := newFakeKeys()
	s := sealedWithA(t, ks)
	b, err := os.ReadFile(s.PinPath())
	if err != nil {
		t.Fatal(err)
	}
	f, _ := s.read()
	if err := os.WriteFile(s.PinPath(), bytes.Replace(b, []byte(headerDigest(f.sealer.h)), []byte(strings.Repeat("0", 64)), 1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenWith(s.Dir(), ks).Add(AddInput{Name: "B", Value: "value-b", Host: "api.example.com"}); !errors.Is(err, ErrSealChanged) {
		t.Fatalf("add = %v, want ErrSealChanged", err)
	}
	if _, _, err := OpenWith(s.Dir(), ks).Resolve("A"); err != nil {
		t.Fatal(err)
	}
	if st, _ := s.Storage(); st.Pin != "changed" {
		t.Fatalf("a read with the key replaced a differing pin: %+v", st)
	}
}

// A CLI change that can seal a downgraded vault seals it again and says so.
func TestChangeResealsADowngradedVaultAndSaysSo(t *testing.T) {
	ks := newFakeKeys()
	s := sealedWithA(t, ks)
	downgrade(t, s)
	cli := OpenWith(s.Dir(), ks)
	if _, err := cli.Add(AddInput{Name: "B", Value: "value-b", Host: "api.example.com"}); err != nil {
		t.Fatal(err)
	}
	if n := cli.Notice(); !strings.Contains(n, "sealed again") {
		t.Fatalf("notice = %q", n)
	}
	mustPin(t, s, pinByKey)
	mustNotHold(t, rawVault(t, s), "value-b")
	if err := capture(s); err != nil {
		t.Fatal(err)
	}
}
