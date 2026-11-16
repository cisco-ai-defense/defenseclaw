//go:build !darwin

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package cli

import "github.com/defenseclaw/defenseclaw/internal/enterprisehooks"

func repairEnterpriseHookUserTargetPlatform(
	enterprisehooks.ManifestTarget,
	enterprisehooks.InstallOptions,
) error {
	return nil
}

func reportEnterpriseHookTargetRepairedPlatform(
	enterprisehooks.ManifestTarget,
	enterprisehooks.InstallResult,
) {
}
