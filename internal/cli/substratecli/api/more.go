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
	"sort"
)

// PolicyQuery asks the policy explain route about one actor ("" for the
// person's default policy), with extra query terms such as host, method or
// tool for a what-if question.
func (c *Client) PolicyQuery(ctx context.Context, actor string, extra map[string]string) (map[string]any, error) {
	q := url.Values{}
	if actor != "" {
		q.Set("actor", actor)
	}
	keys := make([]string, 0, len(extra))
	for k := range extra {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if extra[k] != "" {
			q.Set(k, extra[k])
		}
	}
	var out map[string]any
	return out, c.do(ctx, http.MethodGet, "policy/explain", q, nil, &out)
}

// Migrate moves an actor made by an older kit onto the current kit.
func (c *Client) Migrate(ctx context.Context, atespace, name string) (map[string]any, error) {
	var out map[string]any
	return out, c.do(ctx, http.MethodPost, "actors/"+url.PathEscape(atespace)+"/"+url.PathEscape(name)+"/migrate", nil, map[string]any{}, &out)
}

// HostAllowed asks the policy explain route whether actor's network rules
// allow host. known is false when the gateway cannot say (an older
// gateway, the control API did not answer, any error): then the caller
// keeps its old guess. No policy, or only the DefenseClaw rule after a
// policy conflict, allows no host.
func (c *Client) HostAllowed(ctx context.Context, actor, host string) (allowed, known bool) {
	out, err := c.PolicyQuery(ctx, actor, map[string]string{"host": host})
	if err != nil {
		return false, false
	}
	eg, _ := out["egress"].(map[string]any)
	pol, _ := eg["policy"].(string)
	h, _ := out["host"].(map[string]any)
	v, ok := h["allowed"].(bool)
	switch {
	case pol == "" || pol == "unknown" || !ok:
		return false, false
	case pol == "in force":
		return v, true
	}
	return false, true
}
