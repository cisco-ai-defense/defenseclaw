// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"fmt"
	"path/filepath"
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/daemon"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

func init() {
	// The recovery chain also returns the agent config files a root-run gateway
	// wrote in the account home (GAP-0848).
	daemon.RegisterRootOwnedAgentConfigFiles(connector.RootOwnedAgentConfigFiles)
}

// rootRuntimeStartBlockers is a variable so a test can stand in for root-owned
// files it cannot create as an ordinary user.
var rootRuntimeStartBlockers = daemon.RootOwnedStartBlockers

// failedPIDRecord is a variable for the same reason: a test cannot make root
// the owner of the PID record that the real start preflight refuses.
var failedPIDRecord = daemon.FailedPIDRecord

// rootOwnedRuntimeLeftoversRefusal stops a gateway start or restart that the
// gateway would refuse over state only root can change. A gateway that was
// started with sudo and then stopped leaves it behind, and the account's own
// start then fails inside the daemon with the raw protected-state text. Name
// what is root-owned and the one repair instead, before anything is stopped or
// launched (GAP-0788). A managed install and a Secure Client host keep their
// own trust model, as Doctor's Sudo leftovers row does.
func rootOwnedRuntimeLeftoversRefusal(cfg *config.Config, verb string) error {
	_, refusal := rootOwnedStartRefusal(cfg, verb)
	return refusal
}

// rootOwnedStartRefusal is the refusal of rootOwnedRuntimeLeftoversRefusal and
// the PID records root-owned state keeps the gateway from validating: each
// root-owned PID record by name, and daemon.StoreDirEntry when the root-owned
// install home itself hides both.
func rootOwnedStartRefusal(cfg *config.Config, verb string) (pidBlockers []string, refusal error) {
	if cfg == nil || managed.IsManagedEnterprise(managed.PinnedDeploymentMode()) ||
		managed.IsManagedEnterprise(cfg.DeploymentMode) {
		return nil, nil
	}
	installHome := config.DefaultDataPath()
	blockers, loose := rootRuntimeStartBlockers(cfg.DataDir, installHome, cfg.AIDiscovery.Enabled)
	if len(blockers) == 0 {
		return nil, nil
	}
	paths := make([]string, len(blockers))
	for i, name := range blockers {
		paths[i] = name
		if !filepath.IsAbs(name) {
			paths[i] = filepath.Join(cfg.DataDir, name)
		}
		switch {
		case daemon.NamesGatewayPIDRecord(name):
			pidBlockers = append(pidBlockers, filepath.Base(name))
		case name == daemon.StoreDirEntry && filepath.Clean(cfg.DataDir) == filepath.Clean(installHome):
			pidBlockers = append(pidBlockers, daemon.StoreDirEntry)
		}
	}
	return pidBlockers, fmt.Errorf("cannot %s the gateway: these are root-owned, left by a gateway that was started with sudo, "+
		"and this account cannot use them: %s. %s", verb, strings.Join(paths, ", "),
		daemon.RootLeftoversRemedy(installHome, loose))
}

// refuseOverRootOwnedState explains a refused start or restart whose PID
// records failed validation. The PID check runs before the config is read, so
// a root-owned PID record reached the raw identity error and never the chain.
// When the record that failed is root-owned (or the root-owned install home
// hides it) and root is what denied the account the read, the report and the
// chain replace the identity text: the chain returns the ownership and the
// owner access, which is what clears that failure. Every other refusal keeps
// its own reason first and the root-owned report follows: a record refused for
// its content (malformed, invalid PID), a permission error on a file the
// account owns, and any case where a different PID record is the root-owned
// one. An identity error with no root-owned state is returned unchanged. The
// start is refused in every case.
func refuseOverRootOwnedState(cmd *cobra.Command, verb string, identityErr error) error {
	cfg, _ := loadDaemonConfig(cmd)
	pidBlockers, refusal := rootOwnedStartRefusal(cfg, verb)
	if refusal == nil {
		return identityErr
	}
	failed, rootDenied := failedPIDRecord(identityErr)
	if failed != "" && rootDenied && (slices.Contains(pidBlockers, failed) || slices.Contains(pidBlockers, daemon.StoreDirEntry)) {
		return refusal
	}
	return fmt.Errorf("%w; separately, %s", identityErr, refusal)
}
