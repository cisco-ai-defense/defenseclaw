// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"net/http"

	"github.com/defenseclaw/defenseclaw/internal/substrate/fleet"
)

// FleetStatusDocument returns the administrator status document the gateway
// builds: health, inventory, batches and the cluster checks.
func (c *Client) FleetStatusDocument(ctx context.Context) (fleet.StatusDocument, error) {
	var out fleet.StatusDocument
	return out, c.do(ctx, http.MethodGet, "fleet/status", nil, nil, &out)
}
