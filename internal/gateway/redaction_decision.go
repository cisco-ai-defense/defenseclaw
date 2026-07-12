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
	"sync/atomic"

	"github.com/defenseclaw/defenseclaw/internal/redaction"
)

// managedEnterpriseActive mirrors managed.IsManagedEnterprise(cfg.
// DeploymentMode) at the gateway-package level so request-scoped policy
// propagation and compatibility notification sinks can gate the
// cloud-controlled per-inspection redaction directive on managed_enterprise.
//
// Wired from deployment_mode by NewSidecar and applyConfigReload, alongside
// redaction.SetAgentReasonRedactionDisabled. Reads use atomic.Bool so request
// hot paths stay lock-free.
var managedEnterpriseActive atomic.Bool

// SetManagedEnterpriseActive records whether the running deployment is
// managed_enterprise. Set once from the deployment_mode wiring; tests
// may toggle it under t.Cleanup. Idempotent and atomic.
func SetManagedEnterpriseActive(v bool) { managedEnterpriseActive.Store(v) }

// setManagedEnterpriseRedactionPosture keeps the two process-local managed
// controls synchronized at startup and after a committed hot reload. Canonical
// destination redaction remains generation-owned; this only controls the
// agent-facing reason carve-out and request-scoped cloud directive gate.
func setManagedEnterpriseRedactionPosture(v bool) {
	redaction.SetAgentReasonRedactionDisabled(v)
	SetManagedEnterpriseActive(v)
}

// ManagedEnterpriseActive reports the flag set by
// SetManagedEnterpriseActive.
func ManagedEnterpriseActive() bool { return managedEnterpriseActive.Load() }

// redactionDecisionKey is the private context key under which the
// per-inspection cloud redaction directive rides the request context
// from the evaluate*/proxy inspection sites to the canonical v8 projection
// boundary and compatibility sinks. Kept as an unexported empty struct type so
// no other package can collide with or read it.
type redactionDecisionKey struct{}

// withRedactionDecision returns a child context carrying the
// per-inspection cloud redaction directive (is_redaction_enabled) so
// the emit choke points can stamp it onto the emitted events for the
// async/mirror sinks. It ALSO stamps the fully resolved (managed-gated)
// redaction.SinkPolicy onto the context via redaction.WithSinkPolicy so
// the downstream sink helpers in internal/scanner and internal/audit —
// which take the same ctx but cannot import this package — honor the
// same per-inspection decision.
//
// Outside managed_enterprise the resolved policy is SinkPolicyDefault
// so behavior is unchanged. A nil directive is stored as-is (meaning
// "no directive") so callers can unconditionally stamp the verdict's
// RedactionEnabled without a nil guard.
func withRedactionDecision(ctx context.Context, redactionEnabled *bool) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	ctx = context.WithValue(ctx, redactionDecisionKey{}, redactionEnabled)
	policy := redaction.SinkPolicyDefault
	if managedEnterpriseActive.Load() {
		policy = managedSinkPolicy(redactionEnabled)
	}
	return redaction.WithSinkPolicy(ctx, policy)
}

// managedSinkPolicy resolves a cloud directive to a fail-closed SinkPolicy
// for managed_enterprise: an explicit false => Raw (cloud says store raw),
// while explicit true OR an ABSENT/nil directive => Redact. Treating a
// missing directive as Redact is the managed "fail closed" contract: a
// failed/absent inspect directive must never let a persistent sink emit raw
// post-inspection content under a local DisableAll opt-out. Only callers
// that have already gated on managed_enterprise should use this.
func managedSinkPolicy(directive *bool) redaction.SinkPolicy {
	if directive != nil && !*directive {
		return redaction.SinkPolicyRaw
	}
	return redaction.SinkPolicyRedact
}

// redactionDecisionFromContext returns the per-inspection cloud
// redaction directive stamped by withRedactionDecision, or nil when
// none is present.
func redactionDecisionFromContext(ctx context.Context) *bool {
	if ctx == nil {
		return nil
	}
	v, _ := ctx.Value(redactionDecisionKey{}).(*bool)
	return v
}

// notificationSinkPolicy unpacks the optional variadic SinkPolicy the
// OS-toast dispatchers accept: the first element when present, else
// SinkPolicyDefault (which keeps the historical redaction behavior for
// the test callers that don't pass one).
func notificationSinkPolicy(policy []redaction.SinkPolicy) redaction.SinkPolicy {
	if len(policy) > 0 {
		return policy[0]
	}
	return redaction.SinkPolicyDefault
}

// sinkPolicyFor resolves the redaction SinkPolicy for a post-inspection
// event. Precedence:
//
//   - Outside managed_enterprise: always SinkPolicyDefault (behavior is
//     unchanged — honor the local privacy config / DisableAll).
//   - In managed_enterprise: the cloud directive is authoritative. An
//     explicit event directive wins over the ctx-resolved policy; a
//     present directive maps to SinkPolicyRaw (cloud=false => store raw)
//     or SinkPolicyRedact (cloud=true => force redact, overriding a
//     local DisableAll). An absent event directive honors an explicitly
//     ctx-stamped policy, but FAILS CLOSED to SinkPolicyRedact when no
//     policy was stamped (e.g. a detached/async sink with no inspect
//     directive) so missing directives redact by default.
//
// eventDirective is the decision stamped on the event itself (used by
// the async/mirror sinks that don't share the request ctx); it takes
// precedence over the ctx-resolved policy when non-nil.
func sinkPolicyFor(ctx context.Context, eventDirective *bool) redaction.SinkPolicy {
	if !managedEnterpriseActive.Load() {
		return redaction.SinkPolicyDefault
	}
	if eventDirective != nil {
		return managedSinkPolicy(eventDirective)
	}
	// No event directive: prefer an explicitly stamped ctx policy
	// (withRedactionDecision already resolved it), else fail closed so a
	// managed sink never silently emits raw under a local DisableAll.
	if p := redaction.SinkPolicyFromContext(ctx); p != redaction.SinkPolicyDefault {
		return p
	}
	return redaction.SinkPolicyRedact
}
