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

package usage

import (
	"context"
	"errors"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/substrate/leader"
)

const (
	alice = "https://idp.example#alice"
	bob   = "https://idp.example#bob"
)

func rec(id, owner, batch string, in, out int64) Record {
	return Record{RequestID: id, At: time.Now(), OwnerID: owner, Principal: owner[len(owner)-3:], Atespace: "eng-web",
		Actor: "a-" + owner[len(owner)-3:], ActorUID: "uid-" + owner[len(owner)-3:], BatchID: batch, Provider: "bedrock",
		RequestedModel: "haiku", Model: "haiku", Route: "none", Status: 200,
		Tokens: Tokens{Input: in, Output: out}, UsageSource: SourceStream}
}

func TestFileStoreOwnOnlyAndTotals(t *testing.T) {
	dir := t.TempDir()
	s, err := OpenFileStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	res, err := s.Append(ctx, []Record{rec("r1", alice, "", 10, 5), rec("r2", alice, "b1", 20, 7), rec("r3", bob, "b1", 1, 1)})
	if err != nil || res.Added != 3 {
		t.Fatalf("append %+v %v", res, err)
	}
	// A retried append of the same request is not counted twice.
	if res, _ := s.Append(ctx, []Record{rec("r1", alice, "", 10, 5)}); res.Added != 0 {
		t.Fatalf("duplicate counted %+v", res)
	}
	if _, err := s.Summary(ctx, Filter{}); !errors.Is(err, ErrNoOwner) {
		t.Fatalf("an empty owner must not read everyone: %v", err)
	}
	got, err := s.Summary(ctx, Filter{OwnerID: alice, Records: 10})
	if err != nil {
		t.Fatal(err)
	}
	if got.Totals.Calls != 2 || got.Totals.Input != 30 || got.Totals.Output != 12 || got.Totals.TotalTokens != 42 ||
		len(got.Owners) != 0 || len(got.Records) != 2 || got.CostBasis != "none" {
		t.Fatalf("alice %+v", got)
	}
	for _, r := range got.Records {
		if r.OwnerID != alice {
			t.Fatalf("another person's record %+v", r)
		}
	}
	all, _ := s.Summary(ctx, Filter{AllOwners: true})
	if all.Totals.Calls != 3 || len(all.Owners) != 2 {
		t.Fatalf("all %+v", all)
	}
	b1, _ := s.Summary(ctx, Filter{AllOwners: true, BatchID: "b1", Principal: "BOB"})
	if b1.Totals.Calls != 1 {
		t.Fatalf("batch+principal %+v", b1)
	}
	// Batch scopes are per owner; the atespace scope is shared.
	if n, _ := s.ScopeTotal(ctx, ScopeQuery{Scope: ScopeBatch, OwnerID: alice, ID: "b1"}); n != 27 {
		t.Fatalf("alice b1 %d", n)
	}
	if n, _ := s.ScopeTotal(ctx, ScopeQuery{Scope: ScopeAtespace, ID: "eng-web"}); n != 44 {
		t.Fatalf("atespace %d", n)
	}
	_ = s.Close()
	// Reopen: records and scope totals survive a leader restart.
	s2, err := OpenFileStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	if got, _ := s2.Summary(ctx, Filter{OwnerID: alice}); got.Totals.Calls != 2 {
		t.Fatalf("reopened %+v", got)
	}
	res, _ = s2.Append(ctx, []Record{rec("r4", alice, "b1", 3, 0)})
	if len(res.Scopes) != 2 || res.Scopes[0].Scope != ScopeBatch || res.Scopes[0].Before != 27 || res.Scopes[0].After != 30 {
		t.Fatalf("scopes after reopen %+v", res.Scopes)
	}
}

func TestFileStoreRetentionKeepsScopeTotals(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	clock := func() time.Time { return now }
	s, err := OpenFileStore(dir, Options{Retention: time.Hour, MaxRecords: 2, Now: clock})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for i, id := range []string{"a", "b", "c"} {
		r := rec(id, alice, "b1", 10, 0)
		r.At = now.Add(time.Duration(i) * time.Second)
		if _, err := s.Append(ctx, []Record{r}); err != nil {
			t.Fatal(err)
		}
	}
	got, _ := s.Summary(ctx, Filter{OwnerID: alice})
	if got.Totals.Calls != 2 {
		t.Fatalf("cap not applied %+v", got.Totals)
	}
	// The budget scope still counts the trimmed record.
	if n, _ := s.ScopeTotal(ctx, ScopeQuery{Scope: ScopeBatch, OwnerID: alice, ID: "b1"}); n != 30 {
		t.Fatalf("scope %d", n)
	}
	_ = s.Close()
	b, _ := os.ReadFile(filepath.Join(dir, recordsFile))
	if n := len(splitLines(b)); n > 4 {
		t.Fatalf("record file not compacted: %d lines", n)
	}
}

func splitLines(b []byte) [][]byte {
	var out [][]byte
	start := 0
	for i, c := range b {
		if c == '\n' {
			out = append(out, b[start:i])
			start = i + 1
		}
	}
	return out
}

func TestRemoteAndWriter(t *testing.T) {
	s, err := OpenFileStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	srv := &leader.Server{IsLeader: func() bool { return true }}
	Serve(srv, s)
	hs := httptest.NewServer(srv)
	defer hs.Close()
	remote := &Remote{Client: &leader.Client{BaseURL: hs.URL, HTTP: hs.Client(), Retry: time.Second}}
	var mu sync.Mutex
	var crossed []ScopeTotal
	w := &Writer{Store: remote, Interval: 10 * time.Millisecond, OnResult: func(r AppendResult) {
		mu.Lock()
		defer mu.Unlock()
		for _, sc := range r.Scopes {
			if sc.Scope == ScopeBatch && sc.Before < 25 && sc.After >= 25 {
				crossed = append(crossed, sc)
			}
		}
	}}
	for i := range 10 {
		w.Add(rec(string(rune('a'+i)), alice, "b9", 5, 0))
	}
	w.Close()
	got, err := remote.Summary(context.Background(), Filter{OwnerID: alice, BatchID: "b9"})
	if err != nil || got.Totals.Calls != 10 || got.Totals.Input != 50 {
		t.Fatalf("remote summary %+v %v", got.Totals, err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(crossed) != 1 {
		t.Fatalf("threshold crossed %d times: %+v", len(crossed), crossed)
	}
	if _, err := remote.Summary(context.Background(), Filter{}); !errors.Is(err, ErrNoOwner) {
		t.Fatalf("remote empty owner %v", err)
	}
	if w.Add(rec("late", alice, "", 1, 1)) {
		t.Fatal("closed writer accepted a record")
	}
}
