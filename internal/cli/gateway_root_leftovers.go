// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/daemon"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// rootRuntimeLeftovers is a variable so a test can stand in for root-owned
// files it cannot create as an ordinary user.
var rootRuntimeLeftovers = daemon.RootOwnedRuntimeLeftovers

// rootOwnedRuntimeLeftoversRefusal stops a gateway start or restart that the
// gateway would refuse over runtime files only root can change. A gateway
// that was started with sudo and then stopped leaves them behind, and the
// account's own start then fails inside the daemon with the raw
// protected-state text. Name the files and the one repair instead, before
// anything is stopped or launched (GAP-0788). A managed install and a Secure
// Client host keep their own trust model, as Doctor's Sudo leftovers row does.
func rootOwnedRuntimeLeftoversRefusal(cfg *config.Config, verb string) error {
	if cfg == nil || managed.IsManagedEnterprise(managed.PinnedDeploymentMode()) ||
		managed.IsManagedEnterprise(cfg.DeploymentMode) {
		return nil
	}
	leftovers := rootRuntimeLeftovers(cfg.DataDir)
	if len(leftovers) == 0 {
		return nil
	}
	paths := make([]string, len(leftovers))
	for i, name := range leftovers {
		paths[i] = filepath.Join(cfg.DataDir, name)
	}
	return fmt.Errorf("cannot %s the gateway: these files are root-owned, left by a gateway that was started with sudo, "+
		"and this account cannot use them: %s. %s", verb, strings.Join(paths, ", "),
		daemon.RootLeftoversRemedy(config.DefaultDataPath()))
}
