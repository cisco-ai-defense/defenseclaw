// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package gateway

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// admitAmpSelfHealSetup seeds the protected setup-selected executable receipt
// that native Windows Amp setup requires before it may write the plugin, binds
// the selected executable evidence into opts, and returns the plugin path the
// fixture installed as AMPPluginPathOverride. Delivery-policy fields in opts
// are left untouched so the test still exercises the live resolver.
func admitAmpSelfHealSetup(t *testing.T, dataDir string, opts *connector.SetupOpts) string {
	t.Helper()
	fixture := prepareAmpGatewayAuthorityFixture(t, dataDir)
	opts.AgentVersion = fixture.opts.AgentVersion
	opts.AgentExecutable = fixture.opts.AgentExecutable
	opts.HookContractID = fixture.opts.HookContractID
	return fixture.pluginPath
}
