// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"net/http"
)

// PolicyReset clears an actor's policy_conflict state so the controller
// writes its policy again (administrators only; the call is audited as the
// caller). actor is atespace/name.
func (c *Client) PolicyReset(ctx context.Context, actor, reason string) (map[string]any, error) {
	in := map[string]string{"actor": actor}
	if reason != "" {
		in["reason"] = reason
	}
	var out map[string]any
	return out, c.do(ctx, http.MethodPost, "policy/reset", nil, in, &out)
}
