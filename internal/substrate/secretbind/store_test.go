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

package secretbind

import (
	"context"
	"errors"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// memBackend is a ConfigMap with a resourceVersion.
type memBackend struct {
	mu        sync.Mutex
	raw       []byte
	version   int
	found     bool
	conflicts int // fail this many Puts with ErrConflict
	puts      int
	getErr    error
}

func (m *memBackend) Get(context.Context) ([]byte, string, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.getErr != nil {
		return nil, "", false, m.getErr
	}
	return append([]byte(nil), m.raw...), strconv.Itoa(m.version), m.found, nil
}

func (m *memBackend) Put(_ context.Context, raw []byte, version string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.puts++
	if m.conflicts > 0 {
		m.conflicts--
		m.version++ // someone else wrote
		return ErrConflict
	}
	if m.found && version != strconv.Itoa(m.version) {
		return ErrConflict
	}
	m.raw, m.found = append([]byte(nil), raw...), true
	m.version++
	return nil
}

func bind(owner, name string) Binding {
	return Binding{ID: NewID(), Name: name, Owner: owner, Template: "gitlab", Hosts: []string{"git.corp.example"},
		State: Active, Created: time.Date(2026, 11, 22, 0, 0, 0, 0, time.UTC)}
}

const eng1, eng2 = "pk-eng1-0001", "pk-eng2-0002"

func add(t *testing.T, s *Store, b Binding) {
	t.Helper()
	if err := s.Update(context.Background(), func(d *Doc) error { d.Bindings = append(d.Bindings, b); return nil }); err != nil {
		t.Fatal(err)
	}
}

func TestStoreWriteReadOwnerFilter(t *testing.T) {
	s := New(&memBackend{})
	add(t, s, bind(eng1, "gl-work"))
	add(t, s, bind(eng2, "gl-work"))
	if got := s.ForOwner(eng1); len(got) != 1 || got[0].Owner != eng1 {
		t.Fatalf("ForOwner(eng1) = %+v", got)
	}
	if len(allOf(s)) != 2 || len(s.ForOwner("")) != 0 {
		t.Fatal("All or empty owner wrong")
	}
	// Callers get copies.
	s.ForOwner(eng1)[0].Hosts[0] = "evil.example"
	if s.ForOwner(eng1)[0].Hosts[0] != "git.corp.example" {
		t.Fatal("ForOwner leaks the cached slice")
	}
}

func TestDecodeDropsMalformedAndDuplicates(t *testing.T) {
	good := bind(eng1, "a")
	dupName := bind(eng1, "a")
	badHost := bind(eng1, "b")
	badHost.Hosts = []string{"https://x"}
	badState := bind(eng1, "c")
	badState.State = "approved"
	dotted := bind(eng1, "d")
	dotted.Name = "my.secret" // GAP-0721: telemetry name pattern has no dots
	raw, _ := Doc{Bindings: []Binding{good, dupName, badHost, badState, dotted}}.Encode()
	doc, dropped, err := Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(doc.Bindings) != 1 || doc.Bindings[0].ID != good.ID || len(dropped) != 4 {
		t.Fatalf("kept %d, dropped %v", len(doc.Bindings), dropped)
	}
	if _, _, err := Decode([]byte(`{"version":2,"bindings":[]}`)); err == nil {
		t.Fatal("version 2 accepted")
	}
	if d, _, err := Decode(nil); err != nil || d.Version != Version {
		t.Fatal("empty store must read as empty")
	}
}

func TestRefreshKeepsLastGood(t *testing.T) {
	m := &memBackend{}
	s := New(m)
	add(t, s, bind(eng1, "a"))
	m.mu.Lock()
	m.raw = []byte("{not json")
	m.mu.Unlock()
	if err := s.Refresh(context.Background()); err == nil {
		t.Fatal("bad document accepted")
	}
	if len(allOf(s)) != 1 {
		t.Fatal("bad read dropped the last good document")
	}
	if _, _, err := s.Health(); err == nil {
		t.Fatal("Health hides the read error")
	}
	// A writer never overwrites what a reader cannot parse.
	if err := s.Update(context.Background(), func(*Doc) error { return nil }); err == nil {
		t.Fatal("Update overwrote an unparseable document")
	}
}

func TestUpdateRetriesConflictsThenGivesUp(t *testing.T) {
	m := &memBackend{}
	s := New(m)
	add(t, s, bind(eng1, "a"))
	m.conflicts = 2
	add(t, s, bind(eng1, "b"))
	if len(allOf(s)) != 2 {
		t.Fatal("retry lost the write")
	}
	m.conflicts = 3
	if err := s.Update(context.Background(), func(d *Doc) error { d.Bindings = append(d.Bindings, bind(eng1, "c")); return nil }); !errors.Is(err, ErrConflict) {
		t.Fatalf("after three conflicts err = %v", err)
	}
}

func TestUpdateRefusesBadEntryAndLimit(t *testing.T) {
	s := New(&memBackend{})
	bad := bind(eng1, "x")
	bad.Owner = "short"
	if err := s.Update(context.Background(), func(d *Doc) error { d.Bindings = append(d.Bindings, bad); return nil }); err == nil || !strings.Contains(err.Error(), "owner") {
		t.Fatalf("bad entry written: %v", err)
	}
	err := s.Update(context.Background(), func(d *Doc) error {
		for i := 0; i <= MaxBindings; i++ {
			d.Bindings = append(d.Bindings, bind(eng1, "n"+strconv.Itoa(i)))
		}
		return nil
	})
	if !errors.Is(err, ErrFull) {
		t.Fatalf("over the limit: %v", err)
	}
}

func TestExpired(t *testing.T) {
	b := bind(eng1, "a")
	now := time.Now()
	if b.Expired(now) {
		t.Fatal("no expiry is expired")
	}
	b.Expires = now
	if !b.Expired(now) || b.Expired(now.Add(-time.Second)) {
		t.Fatal("expiry boundary")
	}
}

// TestB1StoreOffStartsNoWatcher: with self-service off the store is nil:
// it reads empty, refuses writes, and Watch starts no goroutine.
func TestB1StoreOffStartsNoWatcher(t *testing.T) {
	var s *Store
	before := runtime.NumGoroutine()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s.Watch(ctx, time.Millisecond) // returns at once
	if runtime.NumGoroutine() > before {
		t.Fatal("a nil store started a goroutine")
	}
	if allOf(s) != nil || s.ForOwner(eng1) != nil || s.Refresh(ctx) != nil {
		t.Fatal("a nil store reads something")
	}
	if err := s.Update(ctx, func(*Doc) error { return nil }); !errors.Is(err, ErrNoStore) {
		t.Fatalf("nil store write: %v", err)
	}
}

// allOf is every binding of the last good read (test only).
func allOf(s *Store) []Binding {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return cloneBindings(s.doc.Bindings)
}
