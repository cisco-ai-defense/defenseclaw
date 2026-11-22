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

package controller_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/defenseclaw/defenseclaw/internal/substrate/ateapi"
	"github.com/defenseclaw/defenseclaw/internal/substrate/controller"
)

// GAP-0481 (E4 shape): an actor DefenseClaw refuses (here an unattested
// template) has its own egress policy, and the access policies do not let
// DefenseClaw delete egress policies there. Every pass failed with
// "remove policy: PermissionDenied", about 40 warnings a minute. Now one
// alert names the actor and the missing right, the passes succeed, and the
// delete is tried again quietly until it works.
func TestGAP0481RefusedPolicyDeleteAlertsOnceAndDoesNotFailThePass(t *testing.T) {
	r := newRig(t, nil)
	r.att.Set("eng-web/claude", controller.Attestation{Reason: "no attestation for the digest", Digest: "sha256:abc"})
	a := r.actor("eng-web", "evil1", ateapi.ActorStateSuspended, "sub-alice")
	ref := ateapi.RefOf(a.GetMetadata())
	_ = r.api.ForeignSetPolicy(ref, []*ateapi.EgressRule{{Https: &ateapi.HttpsRule{Hostnames: []string{"evil.example.com"}}}})
	denied := true
	r.api.Err = func(method, key string) error {
		if denied && method == "DeleteActorEgressPolicy" {
			return status.Error(codes.PermissionDenied, "principal defenseclaw-controller lacks can_delete_egress_policy on actor:eng-web/evil1")
		}
		return nil
	}
	for range 5 {
		if err := r.ctl.Reconcile(context.Background()); err != nil {
			t.Fatalf("a refused delete failed the pass: %v", err)
		}
	}
	alerts := r.sink.Events(controller.EventPolicyWriteFailed)
	if len(alerts) != 1 || alerts[0].Severity != controller.SeverityAlert || !strings.Contains(alerts[0].Message, "can_delete_egress_policy") {
		t.Fatalf("alerts = %+v, want one naming the right", alerts)
	}
	if r.api.Policy(ref) == nil {
		t.Fatal("the fake removed the policy despite the refusal")
	}
	// GAP-0531: the refused delete is retried on a backoff, not every pass.
	if n := r.api.Calls("DeleteActorEgressPolicy"); n != 1 {
		t.Fatalf("delete tried %d times in 5 passes, want 1 (backoff)", n)
	}
	// The right is granted: the pass after the backoff removes the policy.
	denied = false
	r.clk.Add(2 * time.Minute)
	r.pass()
	if r.api.Policy(ref) != nil {
		t.Fatal("the policy stayed after the right was granted")
	}
	if n := len(r.sink.Events(controller.EventPolicyRemoved)); n != 1 {
		t.Fatalf("policy removed records = %d, want 1", n)
	}
}
