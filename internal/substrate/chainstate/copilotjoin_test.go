// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package chainstate

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/copilotargs"
)

// GAP-0269: the leader keeps the Copilot permission join per actor, and a
// retried take (the same request id) gets the first answer, not a second
// consumption.
func TestCopilotJoinOnTheLeaderIsPerActorAndConsumedOnce(t *testing.T) {
	s, err := New(Options{Dir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	a := Actor{Atespace: "eng-web", UID: "3b6c2d1e-8f4a-4b9c-a1d2-5e6f7a8b9c0d"}
	b := Actor{Atespace: "eng-web", UID: "9a1f3c5e-2b7d-4e8f-a0c6-1d3b5f7e9a55"}
	call := []CopilotJoinCall{{Name: "apply_patch", Args: json.RawMessage(`"patch"`)}}
	if _, err := s.CopilotJoinRecord(ctx, CopilotJoinRequest{Actor: a, Scope: "s", Readable: true, Allowed: true, Calls: call}); err != nil {
		t.Fatal(err)
	}
	if out, err := s.CopilotJoinTake(ctx, CopilotJoinRequest{Actor: b, Scope: "s", Tool: "edit"}); err != nil || out.Found {
		t.Fatalf("actor b took actor a's call: %+v %v", out, err)
	}
	out, err := s.CopilotJoinTake(ctx, CopilotJoinRequest{Actor: a, Scope: "s", Tool: "edit"})
	if err != nil || !out.Found || len(out.Calls) != 1 || out.Calls[0].Name != "apply_patch" {
		t.Fatalf("take: %+v %v", out, err)
	}
	if out, _ := s.CopilotJoinTake(ctx, CopilotJoinRequest{Actor: a, Scope: "s", Tool: "edit"}); out.Found {
		t.Fatal("a consumed call was taken twice")
	}
	if _, err := s.CopilotJoinRecord(ctx, CopilotJoinRequest{Actor: a, Scope: strings.Repeat("x", copilotJoinMaxScope+1)}); err == nil {
		t.Fatal("an oversized scope was accepted")
	}
	// The store a gateway uses refuses a call without an actor.
	st := &CopilotJoinStore{ActorOf: func(context.Context) (Actor, bool) { return Actor{}, false }}
	if err := st.Record(ctx, "s", true, true, []copilotargs.NativeCall{{Name: "view"}}); err == nil {
		t.Fatal("a call without an actor reached the leader's join")
	}
}
