//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"os"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

func resolveOwner(_ string, uid, gid int) (int, int, error) {
	return uid, gid, nil
}

func validateHomeOwner(_ string, _ int) error {
	return nil
}

func fileOwnerMatches(_ string, uid int) (bool, int) {
	return true, uid
}

func withOwnerCredentials(_, _ int, fn func() error) error {
	return fn()
}

func chmodOwnedPath(path string, mode os.FileMode) error {
	return os.Chmod(path, mode)
}

func lchownInstallFootprint(_, _ int, _ string, _ connector.AgentPaths, _ []string) error {
	return nil
}
