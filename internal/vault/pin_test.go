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
	"crypto/hpke"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"
)

// swapHeader rewrites the sealed vault's header to a key pair the test
// holds, as a process that can write the vault file could, and returns
// that private key.
func swapHeader(t *testing.T, s *Store) hpke.PrivateKey {
	t.Helper()
	priv, err := suiteKEM.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	var f map[string]any
	if err := json.Unmarshal(rawVault(t, s), &f); err != nil {
		t.Fatal(err)
	}
	h, ok := f["seal"].(map[string]any)
	if !ok {
		t.Fatal("the vault has no seal header")
	}
	h["public_key"] = base64.StdEncoding.EncodeToString(priv.PublicKey().Bytes())
	b, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(s.Path(), b, 0o600); err != nil {
		t.Fatal(err)
	}
	return priv
}

// sealedToSwapped reports whether the vault holds a value the swapped
// key opens: a captured secret the writer of the header can read.
func sealedToSwapped(t *testing.T, s *Store, priv hpke.PrivateKey, want string) bool {
	t.Helper()
	var f file
	if err := json.Unmarshal(rawVault(t, s), &f); err != nil {
		t.Fatal(err)
	}
	sl, err := parseHeader(f.Seal)
	if err != nil {
		t.Fatal(err)
	}
	for i := range f.Entries {
		r := &f.Entries[i]
		ct, err := base64.StdEncoding.DecodeString(r.Sealed)
		if err != nil {
			continue
		}
		if plain, err := hpke.Open(priv, suiteKDF, suiteAEAD, []byte(sl.infoOf(r)), ct); err == nil && string(plain) == want {
			return true
		}
	}
	return false
}

// A process that rewrites the seal header's public key must not get the
// next capture sealed to its key: the gateway refuses the capture and
// writes nothing.
func TestCaptureRefusesASwappedSealHeader(t *testing.T) {
	ks := newFakeKeys()
	s := sealedStore(t, ks)
	if _, err := s.Add(AddInput{Name: "A", Value: "value-a", Host: "api.example.com"}); err != nil {
		t.Fatal(err)
	}
	priv := swapHeader(t, s)
	before := rawVault(t, s)
	_, err := Open(s.Dir()).CaptureAll([]CaptureInput{{Value: fakeGitHub(), Kind: "github-token"}}, time.Second)
	if err == nil {
		if sealedToSwapped(t, s, priv, fakeGitHub()) {
			t.Fatal("the capture was sealed to the swapped public key: whoever wrote the header can open it")
		}
		t.Fatal("the capture was kept in a vault whose header was swapped")
	}
	if !errors.Is(err, ErrSealChanged) {
		t.Fatalf("err = %v, want ErrSealChanged", err)
	}
	if !bytes.Equal(before, rawVault(t, s)) {
		t.Fatal("a refused capture changed the vault")
	}
}

// A sealed vault replaced with a version 1 (plain) vault must not get the
// next capture written in the clear.
func TestCaptureRefusesADowngradedVault(t *testing.T) {
	ks := newFakeKeys()
	s := sealedStore(t, ks)
	if _, err := s.Add(AddInput{Name: "A", Value: "value-a", Host: "api.example.com"}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(s.Path(), []byte(`{"version": 1, "entries": []}`), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Open(s.Dir()).CaptureAll([]CaptureInput{{Value: fakeGitHub(), Kind: "github-token"}}, time.Second)
	if bytes.Contains(rawVault(t, s), []byte(fakeGitHub())) {
		t.Fatal("the capture was written in the clear into a vault that had been sealed")
	}
	if err == nil {
		t.Fatal("the capture was kept in a vault that went from sealed to plain")
	}
	if !errors.Is(err, ErrSealRemoved) {
		t.Fatalf("err = %v, want ErrSealRemoved", err)
	}
}

// A sealed vault that was deleted must not be recreated as a plain vault
// by the next capture.
func TestCaptureRefusesADeletedSealedVault(t *testing.T) {
	ks := newFakeKeys()
	s := sealedStore(t, ks)
	if _, err := s.Add(AddInput{Name: "A", Value: "value-a", Host: "api.example.com"}); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(s.Path()); err != nil {
		t.Fatal(err)
	}
	_, err := Open(s.Dir()).CaptureAll([]CaptureInput{{Value: fakeGitHub(), Kind: "github-token"}}, time.Second)
	if b, rerr := os.ReadFile(s.Path()); rerr == nil && bytes.Contains(b, []byte(fakeGitHub())) {
		t.Fatal("the capture recreated the sealed vault as a plain file")
	}
	if err == nil {
		t.Fatal("the capture was kept after the sealed vault was deleted")
	}
	if !errors.Is(err, ErrSealRemoved) {
		t.Fatalf("err = %v, want ErrSealRemoved", err)
	}
	if _, err := os.Stat(s.Path()); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("a refused capture recreated the vault")
	}
}
