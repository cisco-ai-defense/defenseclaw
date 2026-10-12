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
	"errors"
	"net/http"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/openshell/manager"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/openshell/triage"
	"github.com/defenseclaw/defenseclaw/internal/sandboxrelay"
)

// sandboxDecisionsRelay is the part of the managed gateway's hook-socket
// client (sandboxrelay.Client) the decisions persister uses.
type sandboxDecisionsRelay interface {
	Decide(ctx context.Context, req sandboxrelay.DecisionRequest) (sandboxrelay.DecisionResult, error)
	Decisions(ctx context.Context, registration string) ([]sandboxrelay.Decision, error)
	Events(ctx context.Context, batch sandboxrelay.EventBatch) error
}

// sandboxDecisionsClient is a managed host's sandbox daemon's
// manager.Options.Persist: it hands every ask answer, unblock and user
// block to the managed gateway, which re-checks it against the person's
// floor (sandboxreg.CheckDecision), records the person and keeps what
// lasts in its per-user decisions store. It replaces the config.yaml
// persistence (sandboxConfigPersister) on managed hosts, where the daemon
// has no configuration to write and the person's decisions are theirs
// alone. Being a manager.ManagedAuthority is what runs the manager in
// managed mode.
type sandboxDecisionsClient struct {
	relay sandboxDecisionsRelay
	// registrations names the managed registration the daemon holds for
	// one of its sandboxes (the daemon's own record of its binds); nil
	// knows none.
	registrations func(sandbox string) (string, bool)
	// profiles names the guardrail profile a sandbox's registration
	// matched (manager.ProfileLookup); nil knows none.
	profiles func(sandbox string) (string, bool)
}

var (
	_ manager.ManagedAuthority   = (*sandboxDecisionsClient)(nil)
	_ manager.RegistrationLookup = (*sandboxDecisionsClient)(nil)
	_ manager.ProfileLookup      = (*sandboxDecisionsClient)(nil)
	_ triage.Persister           = (*sandboxDecisionsClient)(nil)
)

// newSandboxDecisionsClient returns the managed daemon's persister over
// the managed gateway's hook-socket client; registrations names the
// registration the daemon bound for a sandbox (SandboxRegistration).
func newSandboxDecisionsClient(relay sandboxDecisionsRelay, registrations func(sandbox string) (string, bool)) *sandboxDecisionsClient {
	return &sandboxDecisionsClient{relay: relay, registrations: registrations}
}

// SandboxRegistration names the managed registration of sandbox, so the
// manager knows a sandbox the daemon registered before its record says
// so (manager.RegistrationLookup).
func (c *sandboxDecisionsClient) SandboxRegistration(sandbox string) (string, bool) {
	if c.registrations == nil {
		return "", false
	}
	return c.registrations(sandbox)
}

// SandboxProfile names the guardrail profile the registration of sandbox
// matched, which the manager's refusals name and quote
// (manager.ProfileLookup).
func (c *sandboxDecisionsClient) SandboxProfile(sandbox string) (string, bool) {
	if c.profiles == nil {
		return "", false
	}
	return c.profiles(sandbox)
}

// AllowAlways and BlockAlways are the config.yaml persistence, which a
// managed host does not have: a managed manager keeps its decisions
// through Decide, for one sandbox's registration, and never calls them.
func (c *sandboxDecisionsClient) AllowAlways(context.Context, string) error {
	return errManagedDecisionNeedsSandbox
}

func (c *sandboxDecisionsClient) BlockAlways(context.Context, string) error {
	return errManagedDecisionNeedsSandbox
}

var errManagedDecisionNeedsSandbox = &sandboxapi.Error{Code: sandboxapi.CodeInvalid,
	Message: "on a managed computer, decisions are kept by your organization's DefenseClaw gateway for one of your sandboxes; name the sandbox"}

// Decide is POST /api/v1/sandbox/decisions.
func (c *sandboxDecisionsClient) Decide(ctx context.Context, req sandboxrelay.DecisionRequest) (sandboxrelay.DecisionResult, error) {
	req.V = sandboxrelay.WireVersion
	res, err := c.relay.Decide(ctx, req)
	if err != nil {
		return sandboxrelay.DecisionResult{}, managedDecisionError(err, req.Host)
	}
	return res, nil
}

// Decisions is GET /api/v1/sandbox/decisions?registration=ID.
func (c *sandboxDecisionsClient) Decisions(ctx context.Context, registration string) ([]sandboxrelay.Decision, error) {
	list, err := c.relay.Decisions(ctx, registration)
	if err != nil {
		return nil, managedDecisionError(err, "")
	}
	return list, nil
}

// Events is POST /api/v1/sandbox/events.
func (c *sandboxDecisionsClient) Events(ctx context.Context, batch sandboxrelay.EventBatch) error {
	batch.V = sandboxrelay.WireVersion
	if err := c.relay.Events(ctx, batch); err != nil {
		return managedDecisionError(err, "")
	}
	return nil
}

// managedDecisionError turns the managed gateway's answer into the
// sandbox API error the CLI shows (manager.ManagedAuthority): a decision
// the floor refuses (sandbox_decision_refused) is the organization's
// refusal with the gateway's own text (which names the rule and ends with
// the person's request-access contact), a gone or unknown registration
// asks for a new sandbox (CodeConflict), an unreachable or overloaded
// gateway fails the decision closed (CodeUnavailable), and any other
// refusal (a missing client header, root, another connector) is the
// gateway's, never taken for the floor's.
func managedDecisionError(err error, host string) error {
	var gwErr *sandboxrelay.Error
	if !errors.As(err, &gwErr) {
		if errors.Is(err, sandboxrelay.ErrGatewayUnreachable) || errors.Is(err, sandboxrelay.ErrSocketUntrusted) {
			return &sandboxapi.Error{Code: sandboxapi.CodeUnavailable,
				Message: "your organization's DefenseClaw gateway can't be reached, so the decision wasn't made; try again"}
		}
		return &sandboxapi.Error{Code: sandboxapi.CodeUpstream, Message: "your organization's DefenseClaw gateway", Detail: err.Error()}
	}
	msg := strings.TrimSpace(gwErr.Message)
	switch {
	case gwErr.Reason == sandboxrelay.ReasonDecisionRefused:
		if msg == "" {
			msg = sandboxapi.AdminMessage
		}
		v := &sandboxapi.Violation{Key: "approvals", Attempted: host, Constraint: "openshell.admin", Admin: true, Message: msg}
		return &sandboxapi.Error{Code: sandboxapi.CodeAdminViolation, Message: msg, Violation: v}
	case gwErr.Reason == sandboxrelay.ReasonRegistrationUnknown || gwErr.Reason == sandboxrelay.ReasonRegistrationRevoked ||
		gwErr.Reason == sandboxrelay.ReasonRegistrationExpired || gwErr.Reason == sandboxrelay.ReasonSubjectChanged:
		return &sandboxapi.Error{Code: sandboxapi.CodeConflict,
			Message: "your organization's DefenseClaw gateway no longer knows this sandbox; start it again with defenseclaw sandbox run"}
	case gwErr.Status == http.StatusTooManyRequests:
		detail := ""
		if gwErr.RetryAfter != "" {
			detail = "retry after " + gwErr.RetryAfter + "s"
		}
		return &sandboxapi.Error{Code: sandboxapi.CodeUnavailable,
			Message: "your organization's DefenseClaw gateway is busy; try again shortly", Detail: detail}
	case gwErr.Status == http.StatusBadRequest:
		return &sandboxapi.Error{Code: sandboxapi.CodeInvalid, Message: firstNonEmptyString(msg, "the decision is not valid")}
	case gwErr.Status == http.StatusForbidden:
		return &sandboxapi.Error{Code: sandboxapi.CodeUpstream,
			Message: "your organization's DefenseClaw gateway refused the request, so the decision wasn't made", Detail: gwErr.Error()}
	}
	return &sandboxapi.Error{Code: sandboxapi.CodeUnavailable,
		Message: "your organization's DefenseClaw gateway couldn't make the decision; try again", Detail: gwErr.Error()}
}
