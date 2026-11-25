//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/substrate/ateapi"
	"github.com/defenseclaw/defenseclaw/internal/substrate/ateapi/ateapifake"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// gap0649Suspender is the fake whose durable suspend takes effect and then
// fails, as an upload error, the 5 min bound or a gateway restart does.
type gap0649Suspender struct{ *ateapifake.Fake }

func (g gap0649Suspender) SuspendActorDurable(ctx context.Context, ref *ateapi.ObjectRef) (*ateapi.Actor, error) {
	if _, err := g.SuspendActor(ctx, ref); err != nil {
		return nil, err
	}
	return nil, status.Error(codes.Unavailable, "upload to object storage failed")
}

// GAP-0649: a durable suspend that took effect and then failed left the
// actor SUSPENDED behind a 502 (an unattended task stalled until someone
// connected). The gateway re-reads it and starts it again; when it cannot,
// the answer says it may be suspended.
func TestGAP0649FailedDurableSuspendStartsTheActorAgain(t *testing.T) {
	ref := ateapi.Ref("eng-web", "alice-1")
	for name, tc := range map[string]struct {
		took      bool   // the suspend took effect before the error
		resumeErr error  // ResumeActor fails with this
		reason    string // the 502 reason
		state     ateapi.ActorState
		resumes   int
	}{
		"suspended, started again": {took: true, reason: "snapshot_failed", state: ateapi.ActorStateRunning, resumes: 1},
		"suspended, no worker":     {took: true, resumeErr: status.Error(codes.ResourceExhausted, "no room"), reason: "snapshot_failed_may_be_suspended", state: ateapi.ActorStateSuspended, resumes: 1},
		"refused before suspend":   {reason: "snapshot_failed", state: ateapi.ActorStateRunning},
	} {
		t.Run(name, func(t *testing.T) {
			f, fake, _ := gap0410Fixture(t, ateapi.ActorStateRunning)
			fake.Err = func(method, _ string) error {
				switch {
				case method == "ResumeActor" && tc.resumeErr != nil:
					return tc.resumeErr
				case method == "SuspendActorDurable" && !tc.took:
					return status.Error(codes.Unavailable, "worker unreachable")
				}
				return nil
			}
			acts := f.api.substrateState().cfg.Actions.(*SubstrateATEActions)
			if tc.took {
				acts.Client = gap0649Suspender{fake}
			}
			rec := f.do(t, f.admin, http.MethodPost, "/api/v1/substrate/actors/eng-web/alice-1/snapshot", "p-alice", "{}")
			if rec.Code != http.StatusBadGateway || !strings.Contains(rec.Body.String(), `"`+tc.reason+`"`) {
				t.Fatalf("snapshot %d %s, want 502 %s", rec.Code, rec.Body, tc.reason)
			}
			a, err := fake.GetActor(context.Background(), ref)
			if err != nil {
				t.Fatal(err)
			}
			if a.GetStatus().GetState() != tc.state || fake.Calls("ResumeActor") != tc.resumes {
				t.Fatalf("after a failed durable suspend: %v, resumes %d; want %v, %d (GAP-0649: the actor stays suspended)", a.GetStatus().GetState(), fake.Calls("ResumeActor"), tc.state, tc.resumes)
			}
		})
	}
}
