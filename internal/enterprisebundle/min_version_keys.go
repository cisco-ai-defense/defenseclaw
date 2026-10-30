// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisebundle

import (
	"strings"

	"golang.org/x/mod/semver"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// CheckKeyProductFloor refuses to sign a config that sets a key only
// 1.0.6 and later read (enterprise.identity.trusted_connectors,
// connectors.agent_gateway) unless the bundle
// carries min_product_version 1.0.6 or later. An older device refuses the
// key as unknown anyway; the floor makes the refusal the documented
// product_too_old, and keeps a rollback to an older build from loading a
// policy it cannot read.
func CheckKeyProductFloor(cfg *config.Config, minProductVersion string) error {
	keys := cfg.UsesMinProductVersion106Keys()
	if len(keys) == 0 {
		return nil
	}
	floor := config.TrustedConnectorsMinProductVersion
	min := strings.TrimSpace(minProductVersion)
	if min == "" || !IsReleaseVersion(min) || semver.Compare("v"+min, "v"+floor) < 0 {
		return refuse(CodeConfigInvalid, "min_product_version",
			"config.yaml sets %s, which DefenseClaw %s and later read; sign with --min-product-version %s or later",
			strings.Join(keys, ", "), floor, floor)
	}
	return nil
}
