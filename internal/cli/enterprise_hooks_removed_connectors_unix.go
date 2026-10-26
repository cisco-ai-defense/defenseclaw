//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package cli

// until 1.1: the managed Linux/macOS removal point for OpenHands and
// OmniGent (GAP-1845). A 1.0.2-1.0.4 standalone guardian set them up in a
// user's home; 1.0.5 no longer ships them. Every apply job of the standalone
// guardian (install, verify, repair, remove, purge: the package upgrade, the
// verify timer and uninstall all run one) first runs their teardown as the
// account, which removes what DefenseClaw wrote, by identity, and nothing
// else. It never fails the job and blocks nothing; what it cannot remove is
// logged under the one removal notice. Delete with
// internal/gateway/connector/removed.go.

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// enterpriseHookWorkerRemovedLog receives the removal notice and leftovers
// (the worker's stderr, which the parent forwards to the guardian log).
var enterpriseHookWorkerRemovedLog io.Writer = os.Stderr

// removeRetiredConnectorsForAccount tears OpenHands and OmniGent down once
// for each DefenseClaw data directory of the request's targets. The Secure
// Client guardian is left alone.
func removeRetiredConnectorsForAccount(ctx context.Context, request enterpriseHookWorkerRequest) {
	if !request.Standalone || strings.TrimSpace(request.Home) == "" {
		return
	}
	seen := map[string]bool{}
	for _, target := range request.Targets {
		dataDir := strings.TrimSpace(target.Options.DataDir)
		if dataDir == "" || !filepath.IsAbs(dataDir) || seen[filepath.Clean(dataDir)] {
			continue
		}
		seen[filepath.Clean(dataDir)] = true
		removeRetiredConnectorsIn(ctx, request.Home, connector.SetupOpts{
			DataDir:           filepath.Clean(dataDir),
			WorkspaceDir:      strings.TrimSpace(target.Options.WorkspaceDir),
			ManagedEnterprise: true,
		})
	}
}

func removeRetiredConnectorsIn(ctx context.Context, home string, opts connector.SetupOpts) {
	restore, err := connector.BindUserHomeDir(home)
	if err != nil {
		return
	}
	defer restore()
	noticed := false
	for _, name := range []string{"openhands", "omnigent"} {
		before, _ := connector.RemovedConnectorLeftovers(name, opts)
		if len(before) == 0 {
			continue
		}
		if retired, ok := connector.RetiredConnector(name); ok {
			_ = retired.Teardown(ctx, opts)
		}
		if !noticed {
			fmt.Fprintf(enterpriseHookWorkerRemovedLog, "[enterprise-hooks] %s\n", connector.RemovedConnectorNotice)
			noticed = true
		}
		left, _ := connector.RemovedConnectorLeftovers(name, opts)
		for _, item := range left {
			fmt.Fprintf(enterpriseHookWorkerRemovedLog, "[enterprise-hooks] removed connector %s left %s: %s; to remove it: %s\n", name, item.Path, item.What, item.Step)
		}
	}
}
