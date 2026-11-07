// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/daemon"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// rootRuntimeStartBlockers is a variable so a test can stand in for root-owned
// files it cannot create as an ordinary user.
var rootRuntimeStartBlockers = daemon.RootOwnedStartBlockers

// rootOwnedRuntimeLeftoversRefusal stops a gateway start or restart that the
// gateway would refuse over state only root can change. A gateway that was
// started with sudo and then stopped leaves it behind, and the account's own
// start then fails inside the daemon with the raw protected-state text. Name
// what is root-owned and the one repair instead, before anything is stopped or
// launched (GAP-0788). A managed install and a Secure Client host keep their
// own trust model, as Doctor's Sudo leftovers row does.
func rootOwnedRuntimeLeftoversRefusal(cfg *config.Config, verb string) error {
	refusal, _ := rootOwnedStartRefusal(cfg, verb)
	return refusal
}

// rootOwnedStartRefusal is the refusal of rootOwnedRuntimeLeftoversRefusal and
// whether root-owned state is the reason a PID record cannot be validated: a
// root-owned PID record, or the root-owned install home itself.
func rootOwnedStartRefusal(cfg *config.Config, verb string) (refusal error, pidCause bool) {
	if cfg == nil || managed.IsManagedEnterprise(managed.PinnedDeploymentMode()) ||
		managed.IsManagedEnterprise(cfg.DeploymentMode) {
		return nil, false
	}
	installHome := config.DefaultDataPath()
	blockers, loose := rootRuntimeStartBlockers(cfg.DataDir, installHome, cfg.AIDiscovery.Enabled)
	if len(blockers) == 0 {
		return nil, false
	}
	paths := make([]string, len(blockers))
	for i, name := range blockers {
		paths[i] = name
		if !filepath.IsAbs(name) {
			paths[i] = filepath.Join(cfg.DataDir, name)
		}
		if daemon.NamesGatewayPIDRecord(name) ||
			(name == daemon.StoreDirEntry && filepath.Clean(cfg.DataDir) == filepath.Clean(installHome)) {
			pidCause = true
		}
	}
	return fmt.Errorf("cannot %s the gateway: these are root-owned, left by a gateway that was started with sudo, "+
		"and this account cannot use them: %s. %s", verb, strings.Join(paths, ", "),
		daemon.RootLeftoversRemedy(installHome, loose)), pidCause
}

// refuseOverRootOwnedState explains a refused start or restart whose PID
// records failed validation. The PID check runs before the config is read, so
// a root-owned PID record reached the raw identity error and never the chain.
// When root-owned state is the reason, the report and the chain replace the
// identity text. When root-owned files exist but the PID record is refused for
// its own reason (an account-owned record that is malformed), returning the
// ownership does not clear it: the identity error and its guidance stay first
// and the root-owned report follows. An identity error with no root-owned
// state is returned unchanged. The start is refused in every case.
func refuseOverRootOwnedState(cmd *cobra.Command, verb string, identityErr error) error {
	cfg, _ := loadDaemonConfig(cmd)
	refusal, pidCause := rootOwnedStartRefusal(cfg, verb)
	switch {
	case refusal == nil:
		return identityErr
	case pidCause:
		return refusal
	default:
		return fmt.Errorf("%w; separately, %s", identityErr, refusal)
	}
}
