//go:build windows

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

import (
	"context"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
)

// enterpriseHookWindowsWSL reconciles the WSL agent-session registry policy
// each guardian pass; replaceable in tests.
var enterpriseHookWindowsWSL = enterprisepolicy.PublishWindowsWSL

// The Codex IDE extension rewrites its own WSL setting (its WSL setup
// command turns it on), and every change reloads the editor window: after
// this many repairs for one account within the window, the guardian only
// reports, so it never keeps an editor in a reload loop.
const (
	wslEditorRepairLimit  = 3
	wslEditorRepairWindow = time.Hour
)

var enterpriseHookWSLEditorRepairs = struct {
	sync.Mutex
	bySID map[string][]time.Time
}{bySID: map[string][]time.Time{}}

// enterpriseHookWSLEditorPass resets, as the user, the Codex IDE
// extension's WSL mode in one account's editor settings
// (enterprise.machine_policy.windows_wsl.editor_settings). Repairs are
// logged at once; findings it leaves and errors only when report is set.
func enterpriseHookWSLEditorPass(stderr io.Writer, target enterprisehooks.TargetCredentials, now time.Time, report bool) {
	if cfg == nil || !cfg.StandaloneEnterprise() {
		return
	}
	mode := cfg.Enterprise.MachinePolicy.WSL().EditorSettings
	if mode == config.WSLEditorSettingsAllow {
		return
	}
	sid := strings.ToUpper(strings.TrimSpace(target.SID))
	enterpriseHookWSLEditorRepairs.Lock()
	recent := enterpriseHookWSLEditorRepairs.bySID[sid][:0:0]
	for _, at := range enterpriseHookWSLEditorRepairs.bySID[sid] {
		if now.Sub(at) < wslEditorRepairWindow {
			recent = append(recent, at)
		}
	}
	enterpriseHookWSLEditorRepairs.bySID[sid] = recent
	backedOff := len(recent) >= wslEditorRepairLimit
	enterpriseHookWSLEditorRepairs.Unlock()
	repair := mode == config.WSLEditorSettingsRepair && !backedOff
	if !repair && !report {
		return
	}
	var findings []enterprisepolicy.WSLEditorFinding
	err := enterpriseForeignHookRunAsTarget(target, func() error {
		var passErr error
		if repair {
			findings, passErr = enterprisepolicy.RepairWSLEditorSettings(target.UserHome)
		} else {
			findings, passErr = enterprisepolicy.ScanWSLEditorSettings(target.UserHome)
		}
		return passErr
	})
	for _, finding := range findings {
		switch {
		case finding.Repaired:
			enterpriseHookWSLEditorRepairs.Lock()
			enterpriseHookWSLEditorRepairs.bySID[sid] = append(enterpriseHookWSLEditorRepairs.bySID[sid], now)
			enterpriseHookWSLEditorRepairs.Unlock()
			fmt.Fprintf(stderr, "defenseclaw: enterprise WSL policy: reset chatgpt.runCodexInWindowsSubsystemForLinux to false in %s\n", finding.Path)
		case !report:
		case finding.WSL && backedOff:
			fmt.Fprintf(stderr, "defenseclaw: enterprise WSL policy: %s turned chatgpt.runCodexInWindowsSubsystemForLinux back on %d times within %s; reporting only until the window passes\n", finding.Path, wslEditorRepairLimit, wslEditorRepairWindow)
		case finding.WSL:
			fmt.Fprintf(stderr, "defenseclaw: enterprise WSL policy: %s sets chatgpt.runCodexInWindowsSubsystemForLinux: true (editor_settings is report)\n", finding.Path)
		}
	}
	if err != nil && report {
		fmt.Fprintf(stderr, "defenseclaw: enterprise WSL policy: editor settings for %s: %v\n", target.UserHome, err)
	}
}

// enterprisePolicyWSLState is the WSL row of `enterprise policy
// show|verify`; replaceable in tests.
var enterprisePolicyWSLState = func(ctx enterprisePolicyContext) (enterprisepolicy.State, error) {
	var homes []string
	profiles, profilesErr := enterpriseHookWindowsEligibleProfilesFor(context.Background(), cfg, ctx.layout.ManifestPath)
	for _, profile := range profiles {
		if strings.TrimSpace(profile.UserHome) != "" {
			homes = append(homes, profile.UserHome)
		}
	}
	state, err := enterprisepolicy.VerifyWindowsWSL(ctx.opts, homes)
	if profilesErr != nil {
		state.Conflicts = append(state.Conflicts, fmt.Sprintf("list enrolled profiles for the editor settings check: %v", profilesErr))
		state.Covered = false
	}
	return state, err
}
