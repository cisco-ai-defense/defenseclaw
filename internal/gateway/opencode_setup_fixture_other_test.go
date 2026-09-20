// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

func prepareOpenCodeSetupAuthorityFixture(_ *testing.T, dataDir string) connector.SetupOpts {
	return connector.SetupOpts{
		DataDir:        dataDir,
		AgentVersion:   "1.18.19",
		HookContractID: "opencode-hooks-v1",
	}
}
