// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import (
	"context"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

func ownUpgradeFixtureForTest(_ *testing.T, _ string) {}

func registerPriorCodexRootForTest(t *testing.T, dataDir, _ string) {
	t.Helper()
	if err := connector.NewCodexConnector().Setup(context.Background(), connector.SetupOpts{
		DataDir: dataDir, APIAddr: "127.0.0.1:18970", APIToken: "test-token", HookFailMode: "closed",
	}); err != nil {
		t.Fatalf("register previous Codex root: %v", err)
	}
}
