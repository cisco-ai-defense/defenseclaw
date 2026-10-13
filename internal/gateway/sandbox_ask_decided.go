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

package gateway

import (
	"context"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/sandboxreg"
	"github.com/defenseclaw/defenseclaw/internal/sandboxrelay"
)

// sandboxHostAlias is how a sandbox names this machine; a decision about it
// is a host-port ask, any other host a network-rule ask.
const sandboxHostAlias = "host.openshell.internal"

// sandboxAskReasonFloorDenied is the registered reason of a decision the
// administrator's floor refused (log.sandbox.ask.decided).
const sandboxAskReasonFloorDenied = "floor_denied"

// sandboxAskOutcome is how one POST decisions ended: refused by the floor,
// or taken (and kept or not).
type sandboxAskOutcome struct {
	Refused bool
	Stored  bool
}

// sandboxRecordAskDecided records the managed gateway's decision on a user's
// ask, unblock or block (log.sandbox.ask.decided, audit action
// sandbox-approval); tests replace it.
var sandboxRecordAskDecided = emitSandboxAskDecided

// sandboxAskDecidedEvent is the record of req, answered by the gateway for
// reg's person. A user block is a denial the person chose and kept; an
// allow or unblock is an approval whose scope the request names; a decision
// the floor refused is a denial with the floor_denied reason.
func sandboxAskDecidedEvent(reg sandboxreg.Registration, req sandboxrelay.DecisionRequest, out sandboxAskOutcome, at time.Time) audit.SandboxAskDecidedEvent {
	ev := audit.SandboxAskDecidedEvent{
		Sandbox: sandboxRecordIdentity(reg), Subject: sandboxRecordSubject(reg), ApprovalID: req.ApprovalID,
		Kind: audit.SandboxApprovalNetworkRule, Host: req.Host, Port: req.Port, Result: audit.SandboxApprovalApproved, Timestamp: at,
	}
	if ev.ApprovalID != "" && !audit.ValidApprovalID(ev.ApprovalID) {
		// The caller's id never decides whether the decision is recorded
		// (GAP-0659): one the record can't carry is left out.
		ev.ApprovalID = ""
	}
	if strings.EqualFold(req.Host, sandboxHostAlias) {
		ev.Kind = audit.SandboxApprovalHostPort
	}
	switch {
	case out.Refused:
		stored := false
		ev.Result, ev.Reason, ev.Stored = audit.SandboxApprovalDenied, sandboxAskReasonFloorDenied, &stored
	case req.Kind == sandboxrelay.DecisionEgressBlock:
		stored := out.Stored
		ev.Result, ev.Stored = audit.SandboxApprovalDenied, &stored
	default:
		stored := out.Stored
		ev.Stored = &stored
		ev.Scope = audit.SandboxApprovalScopeSandbox
		if req.Scope == sandboxrelay.DecisionScopeAlways {
			ev.Scope = audit.SandboxApprovalScopeAlways
		}
	}
	return ev
}

// emitSandboxAskDecided records one decision of reg's person. Should the
// recorder refuse the registration's stamp, the decision is recorded with the
// subject key alone, as the foreign-item records are: the decision stands,
// and an approval resolution must not be lost over a descriptive value.
func emitSandboxAskDecided(ctx context.Context, a *APIServer, reg sandboxreg.Registration, req sandboxrelay.DecisionRequest, out sandboxAskOutcome) {
	r := a.managedSandboxRecorder()
	if r == nil {
		return
	}
	ev := sandboxAskDecidedEvent(reg, req, out, time.Now().UTC())
	if err := r.RecordSandboxAskDecided(ctx, ev); err != nil {
		sandboxRecordFailed("ask decided (stamped)", err)
		ev.Sandbox.Managed = audit.SandboxManaged{RegistrationID: reg.ID, SubjectKey: reg.SubjectKey}
		sandboxRecordFailed("ask decided", r.RecordSandboxAskDecided(ctx, ev))
	}
}
