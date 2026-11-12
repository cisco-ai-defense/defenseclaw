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

package registry

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/substrate/leader"
)

func reg(name, uid, sub string) Registration {
	return Registration{Atespace: "eng-web", Name: name, UID: uid, Connector: "claudecode", Profile: "eng",
		Person: Person{Kind: "person", Issuer: "https://idp.example", Subject: sub, Principal: sub + "@example.com"}}
}

func TestFileStore(t *testing.T) {
	dir := t.TempDir()
	s, err := OpenFileStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := s.Put(ctx, reg("a1", "4f9c3a1e-8d2b-4c77-9e0a-6b5f1d2c3e4a", "alice")); err != nil {
		t.Fatal(err)
	}
	if err := s.Put(ctx, reg("b1", "5f9c3a1e-8d2b-4c77-9e0a-6b5f1d2c3e4b", "bob")); err != nil {
		t.Fatal(err)
	}
	got, ok, _ := s.Get(ctx, "eng-web", "4f9c3a1e-8d2b-4c77-9e0a-6b5f1d2c3e4a")
	if !ok || got.Key != "substrate:eng-web/4f9c3a1e-8d2b-4c77-9e0a-6b5f1d2c3e4a" || got.Person.Subject != "alice" || got.CreatedAt.IsZero() {
		t.Fatalf("get %+v %v", got, ok)
	}
	// Owner and run mode never change.
	bad := reg("a1", "4f9c3a1e-8d2b-4c77-9e0a-6b5f1d2c3e4a", "mallory")
	if err := s.Put(ctx, bad); err == nil {
		t.Fatal("owner changed")
	}
	un := reg("a1", "4f9c3a1e-8d2b-4c77-9e0a-6b5f1d2c3e4a", "alice")
	un.Unattended = true
	if err := s.Put(ctx, un); err == nil {
		t.Fatal("run mode changed")
	}
	// A tombstone sticks.
	del := reg("a1", "4f9c3a1e-8d2b-4c77-9e0a-6b5f1d2c3e4a", "alice")
	del.Deleted = true
	if err := s.Put(ctx, del); err != nil {
		t.Fatal(err)
	}
	if err := s.Put(ctx, reg("a1", "4f9c3a1e-8d2b-4c77-9e0a-6b5f1d2c3e4a", "alice")); err == nil {
		t.Fatal("tombstone undone")
	}
	// Reopen from disk; own-only listing.
	s2, err := OpenFileStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	mine, _ := s2.List(ctx, Filter{OwnerID: "https://idp.example#bob"})
	if len(mine) != 1 || mine[0].Name != "b1" {
		t.Fatalf("bob's list %+v", mine)
	}
	all, _ := s2.List(ctx, Filter{IncludeDeleted: true})
	if len(all) != 2 {
		t.Fatalf("all %d", len(all))
	}
	live, _ := s2.List(ctx, Filter{})
	if len(live) != 1 {
		t.Fatalf("live %d", len(live))
	}
	// Validation.
	for _, r := range []Registration{
		{Atespace: "Bad Space", Name: "x", UID: "6f9c3a1e-8d2b-4c77-9e0a-6b5f1d2c3e4c", Connector: "c", Person: Person{Subject: "s"}},
		{Atespace: "eng", Name: "x", UID: "6f9c3a1e-8d2b-4c77-9e0a-6b5f1d2c3e4c", Connector: "c"},
		{Atespace: "eng", Name: "x", UID: "6f9c3a1e-8d2b-4c77-9e0a-6b5f1d2c3e4c", Connector: "c", Attributed: true, Person: Person{Subject: "s"}},
		{Atespace: "eng", Name: "x", UID: "6f9c3a1e-8d2b-4c77-9e0a-6b5f1d2c3e4c", Connector: "c", Person: Person{Subject: "s"}, Key: "substrate:eng/other"},
	} {
		if err := s.Put(ctx, r); err == nil {
			t.Errorf("accepted %+v", r)
		}
	}
}

func TestRemoteOverLeader(t *testing.T) {
	fs, err := OpenFileStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	srv := &leader.Server{IsLeader: func() bool { return true }}
	Serve(srv, fs)
	hs := httptest.NewServer(srv)
	defer hs.Close()
	r := &Remote{Client: &leader.Client{BaseURL: hs.URL, HTTP: hs.Client(), Retry: time.Second}}
	ctx := context.Background()
	if _, ok, err := r.Get(ctx, "eng-web", "4f9c3a1e-8d2b-4c77-9e0a-6b5f1d2c3e4a"); err != nil || ok {
		t.Fatalf("missing: %v %v", ok, err)
	}
	if err := r.Put(ctx, reg("a1", "4f9c3a1e-8d2b-4c77-9e0a-6b5f1d2c3e4a", "alice")); err != nil {
		t.Fatal(err)
	}
	got, ok, err := r.Get(ctx, "eng-web", "4f9c3a1e-8d2b-4c77-9e0a-6b5f1d2c3e4a")
	if err != nil || !ok || got.Person.Subject != "alice" {
		t.Fatalf("get %+v %v %v", got, ok, err)
	}
	if err := r.Put(ctx, reg("a1", "4f9c3a1e-8d2b-4c77-9e0a-6b5f1d2c3e4a", "mallory")); err == nil {
		t.Fatal("owner change through the leader")
	}
	list, err := r.List(ctx, Filter{OwnerID: "https://idp.example#alice"})
	if err != nil || len(list) != 1 {
		t.Fatalf("list %v %v", list, err)
	}
}
