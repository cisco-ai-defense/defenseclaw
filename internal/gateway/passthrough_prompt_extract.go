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
	"strings"
)

// The passthrough prompt check read only the user turn (substrate-1
// GAP-0196). Prompt-side text elsewhere in the body reached the provider
// uninspected: Responses instructions, system and developer turns (also
// after a user turn), tool results the agent sends back, and a body whose
// keys parse differently depending on the parser. passthroughPrompt
// (proxy_body_walk.go) reads every inspectable text of a request body once,
// for every wire shape the passthrough serves. A body whose text it cannot
// read takes the fail mode: refused in action mode on a managed install or
// in the strict tier, otherwise forwarded with an alert that names the
// reason.

// uninspectablePromptFinding is the finding of a request the proxy cannot
// read.
const uninspectablePromptFinding = "PROXY-PROMPT-UNINSPECTABLE"

// uninspectablePrompt records a request whose prompt the proxy cannot read
// and reports whether it is refused (the reply rule's fail mode,
// refuseUninspectable).
func (p *GuardrailProxy) uninspectablePrompt(ctx context.Context, label, mode, why string) bool {
	refuse := p.refuseUninspectable(ctx, mode)
	v := &ScanVerdict{Action: "alert", Severity: "MEDIUM", Scanner: "proxy",
		Reason: "the request could not be inspected: " + why, Findings: []string{uninspectablePromptFinding}}
	outcome := "forwarded with an alert"
	if refuse {
		v.Action, v.Severity, outcome = "block", "HIGH", "refused"
	}
	fmt.Fprintf(os.Stderr, "[guardrail] request not inspectable %s (%s): %s\n", label, why, outcome)
	p.recordTelemetry(ctx, "prompt", label, v, 0, mode, refuse)
	return refuse
}

// foldPromptKey is the prompt field a body key names, matched as
// encoding/json matches keys (Unicode simple folding: "meſſages" is
// "messages"), or "" for another key.
func foldPromptKey(key string) string {
	for k := range passthroughPromptKeys {
		if strings.EqualFold(key, k) {
			return k
		}
	}
	return ""
}
