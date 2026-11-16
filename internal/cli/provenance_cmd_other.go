// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import (
	"context"

	"github.com/defenseclaw/defenseclaw/internal/version"
)

// managedWindowsGatewayProvenance has no Windows deployment to read here;
// Linux and macOS read the protected hook socket (managedGatewayProvenance).
func managedWindowsGatewayProvenance(context.Context) (version.Provenance, bool, error) {
	return version.Provenance{}, false, nil
}
