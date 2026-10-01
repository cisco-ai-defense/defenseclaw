// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import (
	"errors"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// Unix managed hosts keep the documented service-account export (the
// runtime descriptor names the paths); only Windows resolves a managed
// deployment for an administrator.
func platformAuditExportCallerIsAdministrator() bool { return false }

func platformAuditExportManagedLayout() (managed.StandaloneLayout, error) {
	return managed.StandaloneLayout{}, errors.New("no standalone Windows deployment on this platform")
}
