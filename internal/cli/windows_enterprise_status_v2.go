// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"errors"
	"fmt"
	"os"
	"sort"

	"gopkg.in/yaml.v3"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// The status v2 blocks (enterprisestatus connector_block.go,
// openshell_block.go, identity_block.go) of a standalone Windows status and
// verify. Go assembles them from the installed config, the enumerator's
// manifest and unprotected-agents record, the guardian state and one
// loopback /health read; the PowerShell report is not involved. An enabled
// Hermes target cannot be certified against an unobservable session-only
// HERMES_HOME, so its coverage and security flags are incomplete.

// windowsEnterpriseStatusV2Inputs are the files the connectors block reads.
type windowsEnterpriseStatusV2Inputs struct {
	cfg            *config.Config
	configErr      error
	manifest       []enterprisestatus.ConnectorInstall
	manifestErr    error
	unprotected    []enterprisehooks.UnprotectedAgent
	guardian       []enterprisestatus.ConnectorTarget
	guardianKnown  bool
	machinePolicy  func(connector string) bool
	gatewayHealth  func() ([]byte, error)
	knownConnector func(connector string) bool
}

// windowsEnterpriseStatusV2Read reads the inputs of an installed deployment;
// tests replace it.
var windowsEnterpriseStatusV2Read = readWindowsEnterpriseStatusV2Inputs

var windowsManagedHermesCoverageAudit = func() error {
	return postWindowsManagedCoverageAlert("managed-install-coverage", "managed_hermes_session_home_not_covered", map[string]any{
		"connector": "hermes", "coverage_reason": "session_only_hermes_home_unobservable", "coverage_state": "incomplete",
	})
}

func readWindowsEnterpriseStatusV2Inputs() windowsEnterpriseStatusV2Inputs {
	in := windowsEnterpriseStatusV2Inputs{
		machinePolicy: enterprisehooks.WindowsStandaloneMachinePolicyHook,
		gatewayHealth: windowsStandaloneGatewayHealth,
	}
	registry := connector.NewDefaultRegistry()
	in.knownConnector = func(name string) bool {
		_, ok := registry.Get(name)
		return ok
	}
	in.cfg, in.configErr = loadWindowsEnterpriseStandaloneConfig("")
	layout, err := managed.StandaloneWindowsLayout()
	if err != nil {
		in.manifestErr = err
		return in
	}
	in.manifest, in.manifestErr = readWindowsEnterpriseStatusV2Manifest(layout.ManifestPath)
	// An unreadable record is already reported by
	// applyWindowsEnterpriseUnprotectedAgents.
	in.unprotected, _ = windowsEnterpriseUnprotectedAgentsReader()
	if state, exists, err := loadEnterpriseHookGuardianState(layout.DataDir); err == nil && exists {
		in.guardianKnown = true
		for _, row := range state.Results {
			in.guardian = append(in.guardian, enterprisestatus.ConnectorTarget{
				Connector: row.Connector, OK: row.OK,
				Pending: row.Pending || enterpriseHookAwaitingSignInError(row),
			})
		}
	}
	return in
}

// readWindowsEnterpriseStatusV2Manifest lists the manifest's targets without
// their accounts. Every Windows row names enabled explicitly, as
// readWindowsEnterpriseStandaloneEnrollmentAt counts them.
func readWindowsEnterpriseStatusV2Manifest(path string) ([]enterprisestatus.ConnectorInstall, error) {
	body, err := readWindowsEnterpriseBoundedFile(path, 16<<20)
	if err != nil {
		return nil, err
	}
	var manifest struct {
		Targets []struct {
			Connector    string `yaml:"connector"`
			AgentVersion string `yaml:"agent_version"`
			Enabled      bool   `yaml:"enabled"`
		} `yaml:"targets"`
	}
	if err := yaml.Unmarshal(body, &manifest); err != nil {
		return nil, err
	}
	rows := make([]enterprisestatus.ConnectorInstall, 0, len(manifest.Targets))
	for _, target := range manifest.Targets {
		rows = append(rows, enterprisestatus.ConnectorInstall{Connector: target.Connector, Version: target.AgentVersion, Enabled: target.Enabled})
	}
	return rows, nil
}

// applyWindowsEnterpriseStatusV2 adds the status v2 blocks to a status or
// verify of an installed standalone deployment. Every other action prints no
// block but states the same Hermes and hook-process limits, so ensure,
// install and repair cannot report coverage or security that verify does not
// (as on Linux and macOS).
func applyWindowsEnterpriseStatusV2(result *enterprisestatus.Result) {
	publish := result.Action == "status" || result.Action == "verify"
	in := windowsEnterpriseStatusV2Read()
	block := windowsEnterpriseConnectorsBlock(result, in, publish)
	result.AddHookProcessFailureWarnings(block)
	if !publish {
		return
	}
	// Enterprise OpenShell runs on Linux and macOS only.
	result.OpenShell = enterprisestatus.OpenShellUnsupportedCapability()
	result.Connectors = block
	result.Identity = enterprisestatus.IdentityGatewayNotReady()
	if result.Readiness.Gateway && in.gatewayHealth != nil {
		// A failed read is a gateway that did not report.
		body, _ := in.gatewayHealth()
		result.Identity = enterprisestatus.ParseIdentityHealth(body)
	}
}

// windowsEnterpriseConnectorsBlock is the connectors block. The fail mode is
// the Windows hook renderer's (enterprisehooks.ManagedHookFailMode); a
// connector's hook is in machine policy when the installer reported its
// machine policy (Codex, Claude Code, Cursor) or it is a runtime-only row.
// Only a published block reports which of its details could not be read.
func windowsEnterpriseConnectorsBlock(result *enterprisestatus.Result, in windowsEnterpriseStatusV2Inputs, publish bool) map[string]enterprisestatus.ConnectorState {
	inputs := enterprisestatus.ConnectorInputs{Known: in.knownConnector, Guardian: in.guardian, GuardianKnown: in.guardianKnown}
	cfg := in.cfg
	switch {
	case in.configErr == nil && cfg != nil:
		inputs.ConfigLoaded = true
		inputs.Enabled = enterprisehooks.EffectiveWindowsStandaloneHookConnectors(cfg)
		inputs.Mode = cfg.EffectiveGuardrailModeForConnector
	case publish && !errors.Is(in.configErr, os.ErrNotExist):
		result.AddWarning(enterprisestatus.CodeStatusDetailUnavailable, "connectors: the installed config could not be loaded, "+
			"so effective_mode and effective_hook_fail_mode are not reported")
	}
	switch {
	case in.manifestErr == nil:
		inputs.ManifestRead, inputs.Manifest = true, in.manifest
	case publish && !errors.Is(in.manifestErr, os.ErrNotExist) && !errors.Is(in.manifestErr, os.ErrPermission):
		result.AddWarning(enterprisestatus.CodeStatusDetailUnavailable, "connectors: the enumerator's targets manifest could not be read, "+
			"so detected and versions are not reported")
	}
	for _, agent := range in.unprotected {
		inputs.Unprotected = append(inputs.Unprotected, enterprisestatus.ConnectorInstall{Connector: agent.Connector, Version: agent.Version})
	}
	machine := map[string]bool{}
	for name := range result.MachinePolicy {
		machine[name] = true
	}
	for _, name := range inputs.Enabled {
		if in.machinePolicy != nil && in.machinePolicy(name) {
			machine[name] = true
		}
	}
	for name := range machine {
		inputs.MachinePolicy = append(inputs.MachinePolicy, name)
	}
	sort.Strings(inputs.MachinePolicy)
	failMode := func(name string) string {
		return enterprisehooks.ManagedStatusHookFailMode(cfg, name, "windows", machine[name])
	}
	block, hidden := enterprisestatus.BuildConnectors(inputs, failMode)
	if state, ok := block["hermes"]; ok && state.Enabled &&
		(state.Detected == nil || *state.Detected || state.Targets != nil && state.Targets.Total > 0) {
		state.HooksInstalled = enterprisestatus.HooksInstalledUnknown
		// A persistent-home target cannot prove a session-only HERMES_HOME.
		state.Targets = nil
		block["hermes"] = state
		// The limit is the same for every Hermes account and is reported,
		// not certified: lifecycle verify keeps security incomplete and
		// exits 0 (as on Linux and macOS), Setup's live readiness proves
		// each registered hook, and public hooks verify still refuses to
		// attest the home (GAP-0766, GAP-1433). coverage_complete says the
		// enabled hooks are installed, and they are: a documented platform
		// limit keeps its warning but does not make it false, so a clean
		// 1.0.2 upgrade no longer reads incomplete (GAP-1593).
		result.SecurityComplete = false
		message := "connectors.hermes: NOT COVERED: the guardian's persistent-home registration cannot prove a session-only HERMES_HOME is hooked; Windows managed Hermes coverage cannot be verified"
		result.AddWarning(enterprisestatus.CodeStatusDetailUnavailable, message)
		if result.Installed && result.Readiness.Gateway {
			switch result.Action {
			case "ensure", "install", "upgrade", "repair":
				if err := windowsManagedHermesCoverageAudit(); err != nil {
					result.AddWarning(windowsManagedLaunchAuditUnavailable, "could not audit the unobservable Hermes session home: "+err.Error())
				}
			}
		}
	}
	if publish && hidden > 0 {
		result.AddWarning(enterprisestatus.CodeStatusDetailUnavailable, fmt.Sprintf("connectors: %d agent version(s) not shown: "+
			"they are not plain version strings", hidden))
	}
	return block
}
