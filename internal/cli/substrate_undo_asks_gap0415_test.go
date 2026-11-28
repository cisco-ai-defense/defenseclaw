// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"net/http"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/cli/substratecli/api"
	"github.com/defenseclaw/defenseclaw/internal/substrate/asks"
	"github.com/defenseclaw/defenseclaw/internal/substrate/chainstate"
)

// GAP-0415: after undo the launcher closes the agent's pending asks (the
// request they held went with the folder it put back), and only that
// agent's.
func TestGAP0415UndoClosesTheAgentsAsks(t *testing.T) {
	var denied []string
	f := &fakeAdmin{h: map[string]func(http.ResponseWriter, *http.Request){
		"GET asks": jsonReply(map[string]any{"asks": []map[string]any{
			{"id": "k1", "atespace": "eng-web", "actor": "fix-tests-1", "tool": "curl"},
			{"id": "k2", "atespace": "eng-web", "actor": "other", "tool": "curl"},
		}}),
		"POST asks/k1": func(w http.ResponseWriter, _ *http.Request) {
			denied = append(denied, "k1")
			w.WriteHeader(http.StatusNoContent)
		},
		"POST asks/k2": func(w http.ResponseWriter, _ *http.Request) {
			denied = append(denied, "k2")
			w.WriteHeader(http.StatusNoContent)
		},
	}}
	useFakeAdmin(t, f)
	s, err := substrateOpen(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	n := substrateCloseAsks(context.Background(), s.Client, api.Actor{Atespace: "eng-web", Name: "fix-tests-1"}, "undo")
	if n != 1 || len(denied) != 1 || denied[0] != "k1" {
		t.Fatalf("closed %d: %v", n, denied)
	}
}

// GAP-0415: a revert closes the actor's pending asks, as a crash and a
// delete do.
func TestGAP0415RevertClosesPendingAsks(t *testing.T) {
	store := asks.NewMemory()
	ctx := context.Background()
	_, _ = store.OpenAsk(ctx, asks.Ask{Atespace: "eng-web", Actor: "a1", UID: wireUID1, OwnerID: "o", Host: "example.com"})
	h := substrateLifecycleClosesAsks(func(context.Context, chainstate.LifecycleEvent) (chainstate.LifecycleResult, error) {
		return chainstate.LifecycleResult{}, nil
	}, store, nil, nil)
	if _, err := h(ctx, chainstate.LifecycleEvent{Actor: chainstate.Actor{Atespace: "eng-web", UID: wireUID1}, Event: chainstate.LifecycleReverted}); err != nil {
		t.Fatal(err)
	}
	if p := store.Pending(); len(p) != 0 {
		t.Fatalf("a reverted actor's ask stays pending: %v", p)
	}
}
