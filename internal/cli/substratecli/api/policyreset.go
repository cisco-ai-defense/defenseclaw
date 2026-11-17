// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
)

// PolicyReset clears an actor's policy_conflict state so the controller
// writes its policy again (administrators only; the call is audited as the
// caller). actor is atespace/name. The route names the actor in its path,
// POST /actors/{atespace}/{name}/policy/reset, as every per-actor call does
// (GAP-0397: a relative "policy/reset" with the actor in the body was a 404).
func (c *Client) PolicyReset(ctx context.Context, actor, reason string) (map[string]any, error) {
	atespace, name, ok := strings.Cut(actor, "/")
	if !ok || atespace == "" || name == "" || strings.Contains(name, "/") {
		return nil, errors.New("name the agent as ATESPACE/NAME")
	}
	in := map[string]string{}
	if reason != "" {
		in["reason"] = reason
	}
	var out map[string]any
	return out, c.do(ctx, http.MethodPost, "actors/"+url.PathEscape(atespace)+"/"+url.PathEscape(name)+"/policy/reset", nil, in, &out)
}
