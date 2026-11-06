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
	"fmt"
	"os"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// proxyAuditFailedClosedReason is the reason of the strict or managed block
// of a prompt whose evaluation record could not be written.
const proxyAuditFailedClosedReason = "DefenseClaw could not write the audit record of this prompt, so it was blocked. " +
	"Operators: check the free space of the DefenseClaw data directory and the gateway log."

// proxyDecisionConfig is the configuration a proxy request is decided with:
// its guardrail profile's, else its pinned generation's (withProxyAgent).
func proxyDecisionConfig(ctx context.Context) *config.Config {
	var base *config.Config
	if g := requestGeneration(ctx); g != nil {
		base = g.Config
	}
	if base == nil || base.SecureClientIntegration() {
		return base
	}
	if resolved := resolvedGuardrailProfileFrom(ctx); resolved != nil && resolved.derived != nil {
		return resolved.derived
	}
	return base
}

// promptAuditFailedClosed applies the hook routes' failed-audit tier rule
// (hookAuditFailureResponse) to a proxied prompt whose guardrail evaluation
// record could not be written (GAP-0593). The prompt is the one proxy
// decision that still stands before the upstream call. In the strict tier
// and on a managed install it becomes a block in action mode, whatever the
// guardrail mode; in the default and permissive tiers the prompt goes on
// with a degraded-audit warning in the gateway log. Secure Client, and a
// proxy outside a gateway (no configuration), keep the verdict. It reports
// whether the prompt must now be refused.
func (p *GuardrailProxy) promptAuditFailedClosed(ctx context.Context, verdict *ScanVerdict, mode string, auditErr error) bool {
	if auditErr == nil || verdict == nil || (verdict.Action == "block" && mode == "action") {
		return false
	}
	cfg := proxyDecisionConfig(ctx)
	if cfg == nil || cfg.SecureClientIntegration() {
		return false
	}
	if !managed.IsManagedEnterprise(cfg.DeploymentMode) &&
		cfg.HookPolicyTierForConnector(p.servedConnector()) != config.HookPolicyTierStrict {
		fmt.Fprintf(os.Stderr, "[guardrail] WARNING: DefenseClaw audit is degraded: the prompt was allowed, "+
			"but its evaluation record could not be written: %v\n", auditErr)
		return false
	}
	verdict.Action, verdict.Severity = "block", "HIGH"
	verdict.Reason = proxyAuditFailedClosedReason
	fmt.Fprintf(os.Stderr, "[guardrail] prompt audit persistence failed, prompt blocked: %v\n", auditErr)
	return true
}
