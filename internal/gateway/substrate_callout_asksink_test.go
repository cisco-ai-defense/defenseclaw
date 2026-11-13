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

package gateway

import (
	"context"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/substrate/asks"
	"github.com/defenseclaw/defenseclaw/internal/substrate/ateapi"
	"github.com/defenseclaw/defenseclaw/internal/substrate/ateapi/ateapifake"
	"github.com/defenseclaw/defenseclaw/internal/substrate/calloutapi"
	"github.com/defenseclaw/defenseclaw/internal/substrate/extproc"
)

// The callout's AskSink (extproc.AskClient) against the real admin handler
// (D12, TST-0306): an unattended actor whose profile denies asks is refused
// at once; with queue the ask waits, the owner sees it as unattended, an
// approval releases the next request, and the approved host is not asked
// again. Before this the callout had no AskSink and refused every
// ask-required host, so queue never reached a person.
func TestSubstrateCalloutAskSinkThroughTheAdminHandler(t *testing.T) {
	for _, queue := range []bool{false, true} {
		store := asks.NewMemory()
		fake := ateapifake.New()
		fake.PutActor(&ateapi.Actor{Metadata: &ateapi.ResourceMetadata{Atespace: "eng-web", Name: "bob-1"}})
		f := newSubstrateFixture(t, func(c *SubstrateConfig) {
			c.Asks, c.Policies = asksDirect{store}, fake
			c.UnattendedAsk = func(string) SubstrateUnattendedAsk {
				return SubstrateUnattendedAsk{Queue: queue, Timeout: 10 * time.Minute}
			}
		})
		store.OnApprove = func(ctx context.Context, a asks.Ask) error {
			reg, _, err := f.regs.Get(ctx, a.Atespace, a.UID)
			if err != nil {
				return err
			}
			reg.Approved = append(reg.Approved, a.Host)
			return f.regs.Put(ctx, reg)
		}
		srv := httptest.NewServer(f.admin)
		tok := filepath.Join(t.TempDir(), "token")
		if err := os.WriteFile(tok, []byte(subCallout), 0o600); err != nil {
			t.Fatal(err)
		}
		c, err := extproc.NewAskClient(&extproc.Config{Judge: extproc.JudgeConfig{URL: srv.URL + calloutapi.Path, TokenFile: tok}})
		if err != nil || c == nil {
			t.Fatal(c, err)
		}
		req := extproc.AskRequest{Actor: extproc.ActorRef{Atespace: "eng-web", Name: "bob-1"}, Host: "registry.npmjs.org", Method: "GET", Rule: "ask_hosts:registry.npmjs.org"}
		hold, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
		res, err := c.Ask(hold, req)
		cancel()
		if !queue {
			if err != nil || res.Outcome != extproc.AskDenied || res.Reason != "unattended runs do not ask" {
				t.Fatalf("deny: %+v %v", res, err)
			}
			if p := store.Pending(); len(p) != 0 {
				t.Fatalf("deny left asks: %v", p)
			}
			srv.Close()
			continue
		}
		if err != nil || res.Outcome != extproc.AskPending || res.ID == "" {
			t.Fatalf("queue: %+v %v", res, err)
		}
		pending, _ := store.List(context.Background(), asks.ListRequest{OwnerID: ownerOf(bob).ID(), PendingOnly: true})
		if len(pending) != 1 || !pending[0].Unattended || pending[0].ID != res.ID || pending[0].Expires.Sub(pending[0].Created) != 10*time.Minute {
			t.Fatalf("the owner's view: %+v", pending)
		}
		if _, err := store.Resolve(context.Background(), asks.ResolveRequest{ID: res.ID, Decision: "approve", CallerID: ownerOf(bob).ID()}); err != nil {
			t.Fatal(err)
		}
		res, err = c.Ask(context.Background(), req)
		if err != nil || res.Outcome != extproc.AskApproved {
			t.Fatalf("after the approval: %+v %v", res, err)
		}
		if p := store.Pending(); len(p) != 0 {
			t.Fatalf("an approved host was asked again: %v", p)
		}
		srv.Close()
	}
}
