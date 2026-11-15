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

package cli

import (
	"bytes"
	"context"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/substrate/chainstate"
	"github.com/defenseclaw/defenseclaw/internal/substrate/leader"
	"github.com/defenseclaw/defenseclaw/internal/substrate/registry"
)

// TestSubstrateCalloutLeaderPermissions is GAP-0090: the callout may make
// the chain check and the registration name lookup, and nothing else.
func TestSubstrateCalloutLeaderPermissions(t *testing.T) {
	const callout = "spiffe://cluster.local/ns/dc/sa/defenseclaw-callout"
	p := substrateLeaderPermissions([]string{"spiffe://cluster.local/ns/dc/sa/defenseclaw-gateway"}, []string{callout}, nil)
	got := p[callout]
	want := []string{chainstate.MethodChainEgress, leader.MethodRegistrationLookup}
	if !slices.Equal(got, want) {
		t.Fatalf("callout methods %v, want %v", got, want)
	}
}

// TestSubstrateActorDirectoryOverLeader runs the shipped resolver against
// the leader's registration methods: registered, unregistered, deleted.
func TestSubstrateActorDirectoryOverLeader(t *testing.T) {
	fs, err := registry.OpenFileStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	srv := &leader.Server{IsLeader: func() bool { return true }}
	registry.Serve(srv, fs)
	hs := httptest.NewServer(srv)
	defer hs.Close()
	ctx := context.Background()
	person := registry.Person{Kind: "person", Issuer: "https://idp.example", Subject: "alice"}
	for _, r := range []registry.Registration{
		{Atespace: "eng-web", Name: "run1", UID: "4f9c3a1e-8d2b-4c77-9e0a-6b5f1d2c3e4a", Connector: "claudecode", Profile: "eng", Person: person, Unattended: true},
		{Atespace: "eng-web", Name: "gone", UID: "5f9c3a1e-8d2b-4c77-9e0a-6b5f1d2c3e4b", Connector: "claudecode", Profile: "eng", Person: person, Deleted: true},
	} {
		if err := fs.Put(ctx, r); err != nil {
			t.Fatal(err)
		}
	}
	d := substrateActorDirectory{regs: &registry.Remote{Client: &leader.Client{BaseURL: hs.URL, HTTP: hs.Client(), Retry: time.Second}}}
	rec, live, err := d.ResolveActor(ctx, "eng-web", "run1")
	if err != nil || !live || rec.UID != "4f9c3a1e-8d2b-4c77-9e0a-6b5f1d2c3e4a" || rec.Profile != "eng" || !rec.Unattended {
		t.Fatalf("registered: %+v %v %v", rec, live, err)
	}
	if rec, live, err := d.ResolveActor(ctx, "eng-web", "stranger"); err != nil || !live || rec.UID != "" {
		t.Fatalf("unregistered: %+v %v %v", rec, live, err)
	}
	if _, live, err := d.ResolveActor(ctx, "eng-web", "gone"); err != nil || live {
		t.Fatalf("deleted: %v %v", live, err)
	}
}

// A managed callout refuses to start without the leader (D8, GAP-0090).
func TestSubstrateExtprocManagedNeedsLeader(t *testing.T) {
	cfg := filepath.Join(t.TempDir(), "callout.yaml")
	if err := os.WriteFile(cfg, []byte("managed: true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	saved := substrateExtprocOpts
	t.Cleanup(func() { substrateExtprocOpts = saved })
	substrateExtprocOpts = substrateExtprocFlags{config: cfg, listen: "127.0.0.1:0", insecurePlaintext: true}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var out, errOut bytes.Buffer
	err := runSubstrateExtproc(ctx, &out, &errOut)
	if err == nil || !strings.Contains(err.Error(), "--leader-address") {
		t.Fatalf("managed without a leader: %v", err)
	}
}
