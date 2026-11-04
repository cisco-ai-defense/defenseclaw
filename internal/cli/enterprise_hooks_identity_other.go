//go:build !darwin

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
)

func enterpriseHookPlatformTargetIdentity(string, int) (string, error) {
	return "", nil
}

func enterpriseHookUnresolvedTargetIdentity(_ string, target enterprisehooks.ManifestTarget) string {
	return strings.TrimSpace(target.SID)
}

func enterpriseHookLegacyLedgerRowMatchesPlatform(enterpriseHookReconcileRow, string, string, string) bool {
	return false
}

func reportEnterpriseHookManifestSkippedRowsPlatform(string, []enterprisehooks.ManifestRowSkip) {}

func enterpriseHookWatchFailureToleratedPlatform(error) bool {
	return false
}
