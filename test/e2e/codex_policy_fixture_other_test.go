// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package e2e

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

func runCodexPolicyFixtureIfRequested() (bool, int) { return false, 0 }

func seedCodexPolicyFixture(_ *testing.T, _ string, _ *connector.SetupOpts) {}
