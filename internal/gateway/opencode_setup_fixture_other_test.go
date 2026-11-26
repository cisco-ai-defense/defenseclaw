// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

func prepareOpenCodeSetupAuthorityFixture(t *testing.T, dataDir string) connector.SetupOpts {
	return prepareOpenCodeSetupAuthorityFixtureForVersion(t, dataDir, "2.1.4")
}

// prepareOpenCodeSetupAuthorityFixtureForVersion is the Unix form: the version
// comes from agent_discovery.json, so the options carry rawVersion only.
func prepareOpenCodeSetupAuthorityFixtureForVersion(_ *testing.T, dataDir, rawVersion string) connector.SetupOpts {
	return connector.SetupOpts{
		DataDir:        dataDir,
		AgentVersion:   rawVersion,
		HookContractID: "opencode-hooks-v2",
	}
}
