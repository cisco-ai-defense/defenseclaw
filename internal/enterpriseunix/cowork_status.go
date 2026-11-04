// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"context"
	"errors"
	"slices"
	"strconv"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/coworkaudit"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// coworkLastEvents is the per-account audit lookup; tests replace it.
var coworkLastEvents = coworkaudit.LastEvents

// errCoworkNotAdministrator: the per-account Cowork lookup names accounts,
// so only root runs it.
var errCoworkNotAdministrator = errors.New("the per-account Cowork lookup runs only as root")

// describeCowork adds the cowork block (enterprisestatus.BuildCowork) to a
// standalone status or verify: Claude Cowork runs the Claude Code machine
// policy hooks, so it is covered exactly when the claudecode machine policy
// is in place. Accounts come from the enumerator's targets and from the
// Cowork hook rows of the audit store the installed config raw names
// (Env.auditStorePath).
func (l *lifecycle) describeCowork(cfg *config.Config, raw []byte, block map[string]enterprisestatus.ConnectorState, record *Deployment, targets []enterprisehooks.ManifestTarget) {
	env, r := l.env, l.result
	if !l.statusV2() || r.Profile != managed.ProfileStandalone {
		return
	}
	state := block["claudecode"]
	in := enterprisestatus.CoworkInputs{
		Enabled:        state.Enabled,
		HooksInstalled: state.HooksInstalled,
		Health:         l.gatewayHealthBody,
	}
	if record != nil {
		in.MachinePolicy = slices.Contains(record.MachinePolicyConnectors, enterprisepolicy.ConnectorClaudeCode)
	}
	if cfg != nil {
		in.ManagedHooksOnly = cfg.Enterprise.MachinePolicy.PolicyFor(enterprisepolicy.ConnectorClaudeCode).ManagedHooksOnly
		in.DesktopSurfaceRefused = connector.SurfaceRefused(enterprisepolicy.ConnectorClaudeCode, connector.HostSurfaceDesktop,
			cfg.Enterprise.Enrollment.UnverifiedVersionsFor(enterprisepolicy.ConnectorClaudeCode))
	}
	seen := map[string]bool{}
	for _, target := range targets {
		name := strings.TrimSpace(target.User)
		if !target.IsEnabled() || name == "" || seen[name] {
			continue
		}
		seen[name] = true
		account := enterprisestatus.CoworkEnrolledAccount{Account: name}
		if target.UID != nil {
			account.IDs = append(account.IDs, strconv.Itoa(*target.UID))
		}
		in.Enrolled = append(in.Enrolled, account)
	}
	if env.Geteuid == nil || env.Geteuid() != 0 {
		in.EventsErr = errCoworkNotAdministrator
	} else if auditDB, err := env.auditStorePath(raw); err != nil {
		in.EventsErr = err
	} else {
		in.Events, in.EventsTruncated, in.EventsErr = coworkLastEvents(context.Background(), auditDB)
	}
	r.Cowork = enterprisestatus.BuildCowork(in)
	if env.Geteuid != nil && env.Geteuid() == 0 {
		// Root only: it names accounts and runs codesign as each of them.
		r.Cowork.ClaudeDesktop = l.describeCoworkDesktop(context.Background(), targets)
	}
}
