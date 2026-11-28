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

package api

import (
	"context"
	"net/http"
	"net/url"
)

// PushRequest asks the gateway whether pull --push-branch may push an
// actor's work to its origin (B2 2.4).
type PushRequest struct {
	Host string `json:"host"`
	Repo string `json:"repo"`
	// URL is the https address the review named and the push goes to:
	// https://Host/Repo, with or without .git.
	URL     string `json:"url,omitempty"`
	Branch  string `json:"branch"`
	Head    string `json:"head"`
	Commits int    `json:"commits"`
	Files   int    `json:"files"`
	AskID   string `json:"ask_id,omitempty"`
}

// PushDecision is the gateway's answer: allow, ask (AskID names the ask to
// answer) or deny.
type PushDecision struct {
	Decision  string `json:"decision"`
	Reason    string `json:"reason,omitempty"`
	AskID     string `json:"ask_id,omitempty"`
	Summary   string `json:"summary,omitempty"`
	Profile   string `json:"profile,omitempty"`
	DecidedBy string `json:"decided_by,omitempty"`
	// Grant names the egress push grant an allow opened (GAP-1073):
	// while it is open, egress takes git pushes of the actor only to the
	// approved repository. Empty from a gateway that predates grants;
	// GrantError says why a current one could not open it.
	Grant      string `json:"grant,omitempty"`
	GrantError string `json:"grant_error,omitempty"`
}

// PushGrantClosed is the gateway's answer to closing a grant: Closed is
// false for a grant that expired or was lost; Pushes counts the pushes to
// the approved repository egress checked under it.
type PushGrantClosed struct {
	Closed bool `json:"closed"`
	Pushes int  `json:"pushes"`
}

// PushIntent asks POST /actors/{atespace}/{name}/push?grant=1: an allow
// opens an egress push grant (a query parameter, so a gateway that
// predates grants answers as before).
func (c *Client) PushIntent(ctx context.Context, atespace, name string, in PushRequest) (PushDecision, error) {
	var out PushDecision
	err := c.do(ctx, http.MethodPost, "actors/"+url.PathEscape(atespace)+"/"+url.PathEscape(name)+"/push", url.Values{"grant": {"1"}}, in, &out)
	return out, err
}

// PushGrantClose is DELETE /actors/{atespace}/{name}/push/{grant}.
func (c *Client) PushGrantClose(ctx context.Context, atespace, name, grant string) (PushGrantClosed, error) {
	var out PushGrantClosed
	err := c.do(ctx, http.MethodDelete, "actors/"+url.PathEscape(atespace)+"/"+url.PathEscape(name)+"/push/"+url.PathEscape(grant), nil, nil, &out)
	return out, err
}
