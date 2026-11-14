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

package extproc

import (
	"encoding/json"
	"fmt"

	"github.com/defenseclaw/defenseclaw/internal/openshell/egress"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

// The decision header an allowed request carries to its destination, and
// the error code of a refusal body.
const (
	DecisionHeader = "x-defenseclaw-decision"
	errCodeBlocked = "egress_blocked"
)

// decisionValue is the x-defenseclaw-decision value: allow or alert, and
// nothing that identifies the actor or the rule to the destination.
func decisionValue(v Verdict) string {
	if v.Alert {
		return "alert"
	}
	return "allow"
}

// refusalBody is the JSON body of a refused request: the egress proxy's
// BlockResponse, so agents read one shape on hosts and in clusters. It
// never echoes a request header, path or body: the host is the normalized
// destination and every other value comes from the policy.
func (e *Engine) refusalBody(req *Request, v Verdict) []byte {
	msg := fmt.Sprintf("DefenseClaw blocked egress from actor %s to %s (%s): %s",
		clip(req.Actor.Name, 128), clip(req.Host, 253), v.Category, v.Reason)
	if v.AdminRule != "" {
		msg = sandboxapi.AccessRefused(v.AdminRule, req.Host, v.Profile, req.Actor.Name, e.cfg.RequestAccess)
	}
	body := egress.BlockResponse{
		Error: errCodeBlocked, Message: msg, Host: req.Host,
		Category: egress.Category(v.Category), Reason: v.Reason, Rule: v.Rule, Source: egress.Source(v.Source),
		Feed: v.Feed, FeedVersion: v.FeedVersion, Sandbox: req.Actor.Name,
		HowToUnblock: refusalHint(v),
	}
	b, err := json.Marshal(body)
	if err != nil {
		return []byte(`{"error":"egress_blocked","message":"DefenseClaw blocked this request.","unblockable":false,"how_to_unblock":""}`)
	}
	return b
}

// refusalHint tells the agent what to do next, in the egress proxy's
// voice: tell the user, don't route around it.
func refusalHint(v Verdict) string {
	const dont = " Do not try to reach it another way."
	switch v.Category {
	case findSecretInURL, findSecretInHeader, findSecretInCredential, findSecretInBody, findActorSecret:
		return "Remove the secret from the request. Service credentials are added by the cluster on the hosts they are " +
			"bound to: send the placeholder the profile gives instead. Do not retry with the value encoded another way."
	case CategoryAskPending:
		ref := ""
		if v.AskID != "" {
			ref = " (" + v.AskID + ")"
		}
		return "Tell the user this host needs their approval" + ref + ". Retry once they approve it."
	case CategoryAskDenied:
		return "Tell the user the approval for this host was denied." + dont
	case CategoryURLRule:
		return "Tell the user this actor's profile does not allow this request; only an administrator can change it." + dont
	case CategoryChainEgress:
		return "Tell the user DefenseClaw blocked sending data off the cluster after a secret was read in this session." + dont
	case CategoryMCPToolBlocked:
		return "Tell the user DefenseClaw's tool rules refused this MCP tool call." + dont
	case CategoryUnattributed, CategoryActorNotLive, CategoryCalloutError, CategoryChainUnchecked:
		return "DefenseClaw could not check this request. Retry in a moment; if it keeps failing, tell the user."
	case CategoryBodyUninspected, CategoryPathAmbiguous:
		return "Tell the user DefenseClaw could not read this request the way the server will, so it was not sent; send it in a plain form (no unusual encoding)." + dont
	}
	return "Tell the user DefenseClaw blocked this destination for this actor's profile; only an administrator can " +
		"allow it." + dont
}
