// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/daemon"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
)

// stopPerUserGatewayForPurge stops the account's own per-user watchdog,
// then its per-user gateway, both running from the data directory the
// enterprise purge is about to remove (a personal install from before the
// managed deployment). The per-user worker runs it as the account, before
// the purge. An error means one may still run, so the purge keeps the
// account's state rather than leave an orphan gateway without its files.
func stopPerUserGatewayForPurge(opts enterprisehooks.InstallOptions) error {
	dataDir := strings.TrimSpace(opts.DataDir)
	if dataDir == "" {
		dataDir = filepath.Join(opts.UserHome, ".defenseclaw")
	}
	if _, err := os.Lstat(dataDir); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	// The watchdog first: it would restart the gateway.
	if err := stopWatchdogAt(dataDir, io.Discard); err != nil {
		return fmt.Errorf("its per-user watchdog could not be stopped: %w", err)
	}
	gateway := daemon.New(dataDir)
	running, pid := gateway.IsRunning()
	if !running {
		return nil
	}
	if err := gateway.Stop(defaultStopTimeout); err != nil && !errors.Is(err, daemon.ErrNotRunning) {
		return fmt.Errorf("its per-user gateway (PID %d) could not be stopped: %w", pid, err)
	}
	return nil
}
