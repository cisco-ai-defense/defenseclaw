// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// admitAmpSelfHealSetup is a no-op off Windows: only native Windows Amp setup
// requires protected setup-selected executable evidence. It returns the
// current AMPPluginPathOverride.
func admitAmpSelfHealSetup(t *testing.T, _ string, _ *connector.SetupOpts) string {
	t.Helper()
	return connector.AMPPluginPathOverride
}
