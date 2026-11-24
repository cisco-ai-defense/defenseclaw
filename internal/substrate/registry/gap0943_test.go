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
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/substrate/leader"
)

// relPerson is registry.Person as rel/1.0.10 and rel/1.0.11 decode it: no
// email_unverified.
type relPerson struct {
	Kind      string   `json:"kind"`
	Issuer    string   `json:"issuer"`
	Subject   string   `json:"subject"`
	Principal string   `json:"principal,omitempty"`
	Groups    []string `json:"groups,omitempty"`
}

// relRegistration is the record an older leader decodes: every field of
// Registration, with its Person in the older form.
type relRegistration struct {
	Registration
	Person relPerson `json:"person,omitzero"`
}

// GAP-0943: during a rolling upgrade a follower at this version writes the
// registration of an unverified-email person to a leader that predates the
// mark, whose strict decoder refuses unknown fields. The write still lands,
// without the mark; a verified person's write is one call as before.
func TestRemotePutToAnOlderLeaderGAP0943(t *testing.T) {
	var got []relRegistration
	var calls atomic.Int32
	srv := &leader.Server{IsLeader: func() bool { return true }}
	srv.Handle(leader.MethodRegistrationWrite, leader.Typed(func(_ context.Context, r relRegistration) (putOut, error) {
		calls.Add(1)
		got = append(got, r)
		return putOut{Key: r.Key}, nil
	}))
	hs := httptest.NewServer(countingHandler(srv, nil))
	defer hs.Close()
	rm := &Remote{Client: &leader.Client{BaseURL: hs.URL, HTTP: hs.Client(), Retry: time.Second}}
	ctx := context.Background()

	unv := reg("u1", "4f9c3a1e-8d2b-4c77-9e0a-6b5f1d2c3e4a", "kc-unverified-sub")
	unv.Person.Principal, unv.Person.EmailUnverified = "kc-unverified", true
	if err := rm.Put(ctx, unv); err != nil {
		t.Fatalf("an older leader refused an unverified-email registration: %v", err)
	}
	if len(got) != 1 || got[0].Person.Subject != "kc-unverified-sub" || got[0].Person.Principal != "kc-unverified" || got[0].Name != "u1" || got[0].Connector != "claudecode" {
		t.Fatalf("stored on the older leader: %+v", got)
	}

	calls.Store(0)
	if err := rm.Put(ctx, reg("a1", "5f9c3a1e-8d2b-4c77-9e0a-6b5f1d2c3e4a", "alice")); err != nil {
		t.Fatal(err)
	}
	if n := calls.Load(); n != 1 || len(got) != 2 {
		t.Fatalf("a verified write took %d calls (%d stored)", n, len(got))
	}
}

// GAP-0943: a leader at this version decodes and keeps the mark, in one call.
func TestRemotePutKeepsTheAssuranceMarkGAP0943(t *testing.T) {
	fs, err := OpenFileStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	srv := &leader.Server{IsLeader: func() bool { return true }}
	Serve(srv, fs)
	var calls atomic.Int32
	hs := httptest.NewServer(countingHandler(srv, &calls))
	defer hs.Close()
	rm := &Remote{Client: &leader.Client{BaseURL: hs.URL, HTTP: hs.Client(), Retry: time.Second}}
	ctx := context.Background()
	unv := reg("u1", "4f9c3a1e-8d2b-4c77-9e0a-6b5f1d2c3e4a", "kc-unverified-sub")
	unv.Person.EmailUnverified = true
	if err := rm.Put(ctx, unv); err != nil {
		t.Fatal(err)
	}
	if n := calls.Load(); n != 1 {
		t.Fatalf("the write took %d calls", n)
	}
	r, ok, err := fs.Get(ctx, "eng-web", unv.UID)
	if err != nil || !ok || !r.Person.EmailUnverified || r.Person.Assurance() != AssuranceEmailUnverified {
		t.Fatalf("stored %+v %v %v", r.Person, ok, err)
	}
}

func countingHandler(h http.Handler, n *atomic.Int32) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if n != nil {
			n.Add(1)
		}
		h.ServeHTTP(w, r)
	})
}
