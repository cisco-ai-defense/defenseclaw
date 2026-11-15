//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// machinePolicyRowConsequence says what a machine-policy connector account
// without a row gets: refused under unenrolled_users: deny, else its calls
// still go through machine policy hooks, but are not routed.
func machinePolicyRowConsequence(cfg *config.Config) string {
	if cfg != nil && strings.EqualFold(strings.TrimSpace(cfg.Enterprise.Enrollment.UnenrolledUsers), config.EnterpriseUnenrolledDeny) {
		return "it is not enrolled, so the gateway refuses its tool calls (enrollment.unenrolled_users: deny)"
	}
	return "it is not enrolled, so its model calls are not routed (machine policy still hooks its tool calls)"
}
