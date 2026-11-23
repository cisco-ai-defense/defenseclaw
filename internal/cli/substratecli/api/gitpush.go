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
}

// PushIntent asks POST /actors/{atespace}/{name}/push.
func (c *Client) PushIntent(ctx context.Context, atespace, name string, in PushRequest) (PushDecision, error) {
	var out PushDecision
	err := c.do(ctx, http.MethodPost, "actors/"+url.PathEscape(atespace)+"/"+url.PathEscape(name)+"/push", nil, in, &out)
	return out, err
}
