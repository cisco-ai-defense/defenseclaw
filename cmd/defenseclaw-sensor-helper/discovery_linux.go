// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package main

import (
	"context"
	"log/slog"

	"github.com/defenseclaw/defenseclaw/internal/inventory"
	"github.com/defenseclaw/defenseclaw/internal/sensor/plane"
)

// discoveryReader serves the gateway's AI Discovery read of homes (the
// --home-dirs list, its /home/* and /sessions/* patterns expanded at every
// read): the de-privileged Cowork VM gateway cannot read the session users'
// homes itself (cowork-1-0-8 GAP-0008). The allowlist comes from the
// signature catalog built into this binary, fixed for the helper's life; no
// request can widen it. nil, so nothing is served, when the catalog does not
// load.
func discoveryReader(homes []string, logger *slog.Logger) func(context.Context) (any, error) {
	catalog, err := inventory.LoadAISignatures()
	if err != nil {
		logger.Warn("sensor helper: no discovery reads, the signature catalog did not load", "error", err)
		return nil
	}
	allow := inventory.NewBrokeredHomeAllowlist(catalog)
	logger.Info("sensor helper serves discovery reads", "allowlisted_paths", len(allow))
	return func(ctx context.Context) (any, error) {
		report := inventory.ReadBrokeredHomes(ctx, plane.ExpandHomes(homes), allow)
		refused := 0
		for _, home := range report.Homes {
			refused += home.Refused
		}
		if refused > 0 || report.Truncated {
			logger.Info("sensor helper discovery read", "homes", len(report.Homes),
				"files_read", report.FilesRead, "refused", refused, "truncated", report.Truncated)
		}
		return report, nil
	}
}
