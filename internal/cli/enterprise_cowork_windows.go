// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/coworkaudit"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// windowsCoworkLastEvents is the per-account audit lookup; tests replace it.
var windowsCoworkLastEvents = coworkaudit.LastEvents

// windowsCoworkElevated says this process is an elevated administrator, the
// only caller that may name accounts; tests replace it.
var windowsCoworkElevated = windowsEnterpriseIsElevated

// windowsCoworkDesktopFolders reads an account's Claude Desktop folders and
// engine trust; tests replace it.
var windowsCoworkDesktopFolders = enterprisehooks.WindowsClaudeDesktopFolders

// windowsEnterpriseCoworkBlock is the cowork block of a Windows standalone
// status or verify (enterprisestatus.BuildCowork): Claude Cowork runs the
// Claude Code machine policy hooks of C:\Program Files\ClaudeCode, so it is
// covered when the claudecode connector's hooks are in machine policy and
// installed for every target, and DefenseClaw's drop-in there is in place
// (machine_policy.claudecode owns its entries without a conflict, as the
// runtime descriptor's covered set decides on Linux and macOS). The elevated
// lifecycle reads the audit store auditStore resolves
// (windowsEnterpriseAuditStore) for each enrolled account's last Cowork
// event, and each enrolled account's Claude Desktop engine trust
// (windowsCoworkDesktopState, GAP-0057); accounts are named only in this
// administrator view.
func windowsEnterpriseCoworkBlock(result *enterprisestatus.Result, cfg *config.Config, auditStore func() (string, error),
	block map[string]enterprisestatus.ConnectorState, health []byte) *enterprisestatus.CoworkState {
	if result == nil || (result.Action != "status" && result.Action != "verify") {
		return nil
	}
	state := block["claudecode"]
	policy, listed := result.MachinePolicy["claudecode"]
	in := enterprisestatus.CoworkInputs{
		Enabled: state.Enabled,
		MachinePolicy: state.ManagedHook != nil && *state.ManagedHook &&
			listed && policy.HooksInstalled() == enterprisestatus.HooksInstalledAll,
		HooksInstalled: state.HooksInstalled,
		Health:         health,
	}
	for _, account := range result.Enrollment.Accounts {
		enrolled := enterprisestatus.CoworkEnrolledAccount{Account: account.Account}
		if sid := strings.TrimSpace(account.SID); sid != "" {
			enrolled.IDs = append(enrolled.IDs, sid)
		}
		in.Enrolled = append(in.Enrolled, enrolled)
	}
	if cfg != nil {
		in.ManagedHooksOnly = cfg.Enterprise.MachinePolicy.PolicyFor(enterprisepolicy.ConnectorClaudeCode).ManagedHooksOnly
		in.DesktopSurfaceRefused = connector.SurfaceRefused(enterprisepolicy.ConnectorClaudeCode, connector.HostSurfaceDesktop,
			cfg.Enterprise.Enrollment.UnverifiedVersionsFor(enterprisepolicy.ConnectorClaudeCode))
	}
	elevated := windowsCoworkElevated()
	switch {
	case !elevated:
		in.EventsErr = errors.New("the per-account Cowork lookup runs only for an elevated administrator")
	case auditStore == nil:
		in.EventsErr = errors.New("the installed config names no audit store")
	default:
		if path, err := auditStore(); err != nil {
			in.EventsErr = err
		} else {
			in.Events, in.EventsTruncated, in.EventsErr = windowsCoworkLastEvents(context.Background(), path)
		}
	}
	cowork := enterprisestatus.BuildCowork(in)
	if elevated {
		cowork.ClaudeDesktop = windowsCoworkDesktopState(result.Enrollment.Accounts, windowsCoworkDesktopFolders)
	}
	return cowork
}

// windowsEnterpriseAuditStore is the audit store the gateway opens for the
// installed config of layout: config.LocalAuditStorePath, the resolution of
// the gateway start and `audit export`, with the layout's data folder as the
// default and the service pins loadWindowsEnterpriseStandaloneConfig sets.
// The lifecycle's decode of that config is not used: it ignores
// observability.local.path (cowork-1-0-8 GAP-0025).
func windowsEnterpriseAuditStore(layout managed.StandaloneLayout) (string, error) {
	raw, err := readConfigV8Source(layout.ConfigPath)
	if err != nil {
		return "", fmt.Errorf("the installed config names no audit store: %w", err)
	}
	restore := setTemporaryEnvironment(map[string]string{
		managed.ConfigPathEnv:            layout.ConfigPath,
		"DEFENSECLAW_HOME":               layout.DataDir,
		managed.DeploymentModeEnv:        managed.DeploymentModeManagedEnterprise,
		managed.EnterpriseProfileEnv:     managed.ProfileStandalone,
		managed.WindowsServiceAccountEnv: layout.ServiceUser,
	})
	defer restore()
	path, err := config.LocalAuditStorePath(layout.ConfigPath, config.V8ManagedChecksView(raw),
		config.ObservabilityV8CompileOptions{DefaultDataDir: layout.DataDir})
	if err != nil {
		return "", fmt.Errorf("the installed config names no audit store: %w", err)
	}
	return strings.TrimSpace(path), nil
}
