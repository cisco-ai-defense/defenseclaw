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
	"time"
)

// Revocation is an ended sign-in as the gateway answers it (B5.1): one
// token (scope "this") or every sign-in of a person made before NotBefore
// (scope "all"). Closed is how many open terminals the answering gateway
// replica closed.
type Revocation struct {
	Person    string    `json:"person"`
	Principal string    `json:"principal,omitempty"`
	Scope     string    `json:"scope,omitempty"`
	NotBefore time.Time `json:"not_before,omitempty"`
	At        time.Time `json:"at,omitempty"`
	Until     time.Time `json:"until,omitempty"`
	By        string    `json:"by,omitempty"`
	Reason    string    `json:"reason,omitempty"`
	Closed    int       `json:"closed"`
	Lifted    bool      `json:"lifted,omitempty"`
}

// EndSignin ends the caller's own sign-in on the cluster: scope "this" (the
// token it sends, and the other tokens of the same sign-in in also: the ID
// token and the access token) or "all" (every sign-in of the caller made
// before now). A gateway that can't end sign-ins answers 404.
func (c *Client) EndSignin(ctx context.Context, scope string, also ...string) (Revocation, error) {
	var out Revocation
	in := map[string]any{"scope": scope}
	if len(also) > 0 {
		in["also"] = also
	}
	return out, c.do(ctx, http.MethodPost, "signin/revoke", nil, in, &out)
}

// EndSigninsOf ends every sign-in of user (a principal or issuer#subject)
// made before now (administrators).
func (c *Client) EndSigninsOf(ctx context.Context, user, reason string) (Revocation, error) {
	var out Revocation
	return out, c.do(ctx, http.MethodPost, "admin/revocations", nil, map[string]string{"user": user, "reason": reason}, &out)
}

// LiftSigninEnd removes a person-wide end early (administrators).
func (c *Client) LiftSigninEnd(ctx context.Context, user string) (Revocation, error) {
	var out Revocation
	return out, c.do(ctx, http.MethodDelete, "admin/revocations", url.Values{"user": {user}}, nil, &out)
}

// SigninEnds lists the active person-wide ends (administrators).
func (c *Client) SigninEnds(ctx context.Context) ([]Revocation, error) {
	var out struct {
		Revocations []Revocation `json:"revocations"`
	}
	return out.Revocations, c.do(ctx, http.MethodGet, "admin/revocations", nil, nil, &out)
}
