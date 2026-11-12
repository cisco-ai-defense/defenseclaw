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
	"net/http"
	"os"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// A provider reply the passthrough proxy cannot read (GAP-0128): an
// encoding the transport did not decode (the proxy asks for gzip only, so
// br, zstd, deflate or a stacked "gzip, br" is unsolicited), or an AWS
// eventstream it cannot frame. It is never passed silently: in action mode
// a managed install and the strict tier refuse it, every other case
// forwards it with an alert (log, audit and telemetry through the verdict
// path). Secure Client keeps its own pipeline unchanged.

// uninspectableReplyFinding is the finding of such a verdict.
const uninspectableReplyFinding = "PROXY-REPLY-UNINSPECTABLE"

// uninspectableEncoding is the Content-Encoding a reply still carries after
// the transport: "" when there is none or it is identity.
func uninspectableEncoding(h http.Header) string {
	v := strings.ToLower(strings.TrimSpace(strings.Join(h.Values("Content-Encoding"), ", ")))
	if v == "" || v == "identity" {
		return ""
	}
	return v
}

// proxyRequestConnector is the connector a proxy request is decided for:
// an Agent Substrate actor's registration, else the proxy's.
func (p *GuardrailProxy) proxyRequestConnector(ctx context.Context) string {
	if isSubstrateActorRequest(ctx) {
		if reg, ok := substrateRegistrationFrom(ctx); ok {
			return config.NormalizeConnectorName(reg.Connector)
		}
	}
	return p.servedConnector()
}

// refuseUninspectable reports whether a reply the proxy cannot read is
// refused for this request (action mode on a managed install or in the
// strict tier).
func (p *GuardrailProxy) refuseUninspectable(ctx context.Context, mode string) bool {
	if mode != "action" || p.secureClient.Load() {
		return false
	}
	if ManagedEnterpriseActive() {
		return true
	}
	cfg := proxyDecisionConfig(ctx)
	return cfg != nil && cfg.HookPolicyTierForConnector(p.proxyRequestConnector(ctx)) == config.HookPolicyTierStrict
}

// uninspectableReply records a reply the proxy cannot read and reports
// whether it is refused.
func (p *GuardrailProxy) uninspectableReply(ctx context.Context, label, mode, why string) bool {
	refuse := p.refuseUninspectable(ctx, mode)
	v := &ScanVerdict{Action: "alert", Severity: "MEDIUM", Scanner: "proxy",
		Reason: "the provider reply could not be inspected: " + why, Findings: []string{uninspectableReplyFinding}}
	outcome := "forwarded with an alert"
	if refuse {
		v.Action, v.Severity, outcome = "block", "HIGH", "refused"
	}
	fmt.Fprintf(os.Stderr, "[guardrail] reply not inspectable %s (%s): %s\n", label, why, outcome)
	p.recordTelemetry(ctx, "completion", label, v, 0, mode, refuse)
	return refuse
}
