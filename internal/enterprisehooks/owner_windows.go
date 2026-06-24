//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import "github.com/defenseclaw/defenseclaw/internal/gateway/connector"

func resolveOwner(_ string, uid, gid int) (int, int, error) {
	return uid, gid, nil
}

func fileOwnerMatches(_ string, uid int) (bool, int) {
	return true, uid
}

func chownInstallFootprint(_, _ int, _ string, _ connector.AgentPaths, _ []string) error {
	return nil
}
