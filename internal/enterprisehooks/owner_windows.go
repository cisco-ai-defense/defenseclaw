//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"fmt"
	"os"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

var errEnterpriseHooksUnsupportedWindows = fmt.Errorf("enterprise hook guardian is unsupported on Windows until SID impersonation, DACL validation, and reparse-safe writes are implemented")

func resolveOwner(_ string, uid, gid int) (int, int, error) {
	return uid, gid, errEnterpriseHooksUnsupportedWindows
}

func validateHomeOwner(_ string, _ int) error {
	return errEnterpriseHooksUnsupportedWindows
}

func fileOwnerMatches(_ string, uid int) (bool, int) {
	return false, uid
}

func withOwnerCredentials(_, _ int, fn func() error) error {
	return errEnterpriseHooksUnsupportedWindows
}

func chmodOwnedPath(path string, mode os.FileMode) error {
	return errEnterpriseHooksUnsupportedWindows
}

func lchownInstallFootprint(_, _ int, _ string, _ connector.AgentPaths, _ []string) error {
	return errEnterpriseHooksUnsupportedWindows
}
