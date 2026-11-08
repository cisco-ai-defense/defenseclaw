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
	"github.com/defenseclaw/defenseclaw/internal/accountjoin"
	"os"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
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
	cfg           *config.Config
	configErr     error
	manifest      []enterprisestatus.ConnectorInstall
	manifestErr   error
	unprotected   []enterprisehooks.UnprotectedAgent
	guardian      []enterprisestatus.ConnectorTarget
	guardianKnown bool
	machinePolicy func(connector string) bool
	// machinePolicyStates inspects, read-only, the vendor machine policy
	// of the named connectors under the installed config (nil: not read).
	machinePolicyStates func(installed *config.Config, names []string) (map[string]enterprisestatus.MachinePolicyState, error)
	gatewayHealth       func() ([]byte, error)
	knownConnector      func(connector string) bool
	// auditStore resolves the audit store the gateway opens (nil: none);
	// only the elevated Cowork lookup calls it.
	auditStore func() (string, error)
	// accountJoin computes the account join keys (nil: omitted); the
	// result carries only their summary.
	accountJoin func() *accountjoin.Report
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
		machinePolicy:       enterprisehooks.WindowsStandaloneMachinePolicyHook,
		machinePolicyStates: inspectWindowsEnterpriseMachinePolicy,
		gatewayHealth:       windowsStandaloneGatewayHealth,
	}
	registry := connector.NewDefaultRegistry()
	in.knownConnector = func(name string) bool {
		_, ok := registry.Get(name)
		return ok
	}
	in.cfg, in.configErr = loadWindowsEnterpriseStandaloneConfig("")
	layout, err := windowsManagedLayout.standalone()
	if err != nil {
		in.manifestErr = err
		return in
	}
	in.accountJoin = func() *accountjoin.Report { return windowsAccountJoinReport(in.cfg, layout) }
	in.auditStore = func() (string, error) { return windowsEnterpriseAuditStore(layout) }
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

// windowsEnterpriseVendorFolderLink is the link that sits on the path of the
// machine-policy folder of a connector, "" when none. A seam for tests.
var windowsEnterpriseVendorFolderLink = func(connectorName string) string {
	link, _ := enterprisehooks.WindowsManagedConnectorFolderLink(connectorName)
	return link
}

// windowsEnterpriseLinkedConnectors are the connectors whose machine-policy
// folder a link can keep, with the name used in the warning.
var windowsEnterpriseLinkedConnectors = []struct{ connector, label, code string }{
	{"codex", "Codex", "codex_machine_folder_link"},
	{"cursor", "Cursor", "cursor_machine_folder_link"},
	{"claudecode", "Claude Code", "claudecode_machine_folder_link"},
}

// noteWindowsEnterpriseVendorFolderLinks names, for status and verify, a link at
// the machine-policy folder of Codex, Cursor or Claude Code with the command
// that removes it. The hook guardian never writes through the link: it fails
// the targets of that connector and cannot recreate or repair the folder until
// an administrator removes it (GAP-0856, GAP-0879).
func noteWindowsEnterpriseVendorFolderLinks(result *enterprisestatus.Result) {
	for _, entry := range windowsEnterpriseLinkedConnectors {
		if _, configured := result.MachinePolicy[entry.connector]; !configured || windowsEnterpriseResultHasWarning(result, entry.code) {
			continue
		}
		link := windowsEnterpriseVendorFolderLink(entry.connector)
		if link == "" {
			continue
		}
		result.AddWarning(entry.code, fmt.Sprintf("a link or a non-folder sits at %s on the path of the %s machine-policy folder; "+
			"DefenseClaw does not follow, change or remove it, so the hook guardian cannot recreate or repair the folder and %s is not protected until it is gone; "+
			"as an administrator, remove the link with: cmd /c rmdir \"%s\" (it removes the link only, not its target); the guardian then recreates the folder on its next pass",
			link, entry.label, entry.label, link))
	}
}

// noteWindowsEnterprisePendingTransactionLink is for status and verify of a
// deployment whose lifecycle transaction is pending: when a link sits on the path
// of the Codex, Cursor or Claude Code machine-policy folder, it is named as the
// likely cause, with the command that removes it. DefenseClaw never writes
// through the link, so the rollback or the recovery stops at it and the services
// stay stopped until an administrator removes the link and runs the recovery step
// (GAP-0900). No pending transaction or no link: nothing is added.
func noteWindowsEnterprisePendingTransactionLink(result *enterprisestatus.Result) {
	if !result.TransactionPending {
		return
	}
	for _, entry := range windowsEnterpriseLinkedConnectors {
		link := windowsEnterpriseVendorFolderLink(entry.connector)
		if link == "" {
			continue
		}
		result.AddWarning("transaction_pending_link", fmt.Sprintf("a lifecycle transaction is pending and the DefenseClaw services stay stopped until it is recovered; "+
			"a link or a non-folder at %s on the path of the %s machine-policy folder is the likely cause, because DefenseClaw does not write through it; "+
			"as an administrator, remove the link with: cmd /c rmdir \"%s\" (it removes the link only, not its target), then run the recovery step named above",
			link, entry.label, link))
	}
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
	if publish {
		noteWindowsEnterpriseVendorFolderLinks(result)
	}
	in := windowsEnterpriseStatusV2Read()
	applyWindowsEnterpriseCoworkStatus(result, in.cfg)
	var coverage map[string]string
	if publish {
		coverage = applyWindowsEnterpriseMachinePolicyEntries(result, in)
	}
	block := windowsEnterpriseConnectorsBlock(result, in, coverage, publish)
	result.AddHookProcessFailureWarnings(block)
	if !publish {
		return
	}
	// Enterprise OpenShell runs on Linux and macOS only.
	result.OpenShell = enterprisestatus.OpenShellUnsupportedCapability()
	result.Connectors = block
	result.Identity = enterprisestatus.IdentityGatewayNotReady()
	var health []byte
	if result.Readiness.Gateway && in.gatewayHealth != nil {
		// A failed read is a gateway that did not report.
		health, _ = in.gatewayHealth()
		result.Identity = enterprisestatus.ParseIdentityHealth(health)
	}
	result.Cowork = windowsEnterpriseCoworkBlock(result, in.cfg, in.auditStore, block, health)
	if in.accountJoin != nil {
		if report := in.accountJoin(); report != nil {
			summary := report.Summary()
			result.AccountJoin = &summary
		}
	}
}

// windowsEnterpriseConnectorsBlock is the connectors block. The fail mode is
// the Windows hook renderer's (enterprisehooks.ManagedHookFailMode); a
// connector's hook is in machine policy when the installer reported its
// machine policy (Codex, Claude Code, Cursor) or it is a runtime-only row.
// coverage is hooks_installed from each inspected machine policy, used for a
// connector no account row is counted for (as on Linux and macOS): the one
// machine-wide Claude Code drop-in is in place before any account enrolls.
// It is used only once the guardian state was read: every Windows entry
// whose hooks_installed is known carries targets (the lifecycle schema), and
// a connector counted from its machine policy has zero of them.
// Only a published block reports which of its details could not be read.
func windowsEnterpriseConnectorsBlock(result *enterprisestatus.Result, in windowsEnterpriseStatusV2Inputs, coverage map[string]string, publish bool) map[string]enterprisestatus.ConnectorState {
	if !in.guardianKnown {
		coverage = nil
	}
	inputs := enterprisestatus.ConnectorInputs{Known: in.knownConnector, Guardian: in.guardian, GuardianKnown: in.guardianKnown,
		MachinePolicyCoverage: coverage}
	cfg := in.cfg
	switch {
	case in.configErr == nil && cfg != nil:
		inputs.ConfigLoaded = true
		inputs.Enabled = enterprisehooks.EffectiveWindowsStandaloneHookConnectors(cfg)
		inputs.Disabled = cfg.Guardrail.DisabledConnectors()
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
	for name := range coverage {
		if state, ok := block[name]; ok && state.Targets == nil && state.HooksInstalled != enterprisestatus.HooksInstalledUnknown {
			state.Targets = &enterprisestatus.ConnectorTargets{}
			block[name] = state
		}
	}
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

// applyWindowsEnterpriseMachinePolicyEntries fills, for status and verify,
// each machine_policy entry's owned_entries, foreign_entries,
// higher_precedence and conflicts from a read-only inspection of its vendor
// machine policy files (what `enterprise policy verify` reports), and
// returns the hooks_installed value each inspected policy gives. The
// installer's report says only whether a policy is attested in force, so
// every Windows entry read owned_entries 0 since the entries were added, and
// the Cowork block, which needs DefenseClaw's Claude Code drop-in in place,
// said "not configured" beside a complete managed-settings.d
// 90-defenseclaw.json (cowork-1-0-8 GAP-0028). effective_lock, ownership
// and lock stay the installer's attestation and settings. A policy that was
// not read is hooks_installed unknown, as on Linux and macOS
// (machinePolicyCoverage), never none: the hooks may well be in place.
func applyWindowsEnterpriseMachinePolicyEntries(result *enterprisestatus.Result, in windowsEnterpriseStatusV2Inputs) map[string]string {
	if len(result.MachinePolicy) == 0 || in.machinePolicyStates == nil {
		return nil
	}
	names := make([]string, 0, len(result.MachinePolicy))
	for name := range result.MachinePolicy {
		names = append(names, name)
	}
	sort.Strings(names)
	var inspected map[string]enterprisestatus.MachinePolicyState
	var err error
	if in.cfg == nil {
		err = errors.New("the installed config could not be loaded")
	} else {
		inspected, err = in.machinePolicyStates(in.cfg, names)
	}
	coverage := make(map[string]string, len(names))
	var unread []string
	for _, name := range names {
		state, ok := inspected[name]
		if !ok {
			coverage[name] = enterprisestatus.HooksInstalledUnknown
			unread = append(unread, name)
			continue
		}
		entry := result.MachinePolicy[name]
		entry.OwnedEntries, entry.ForeignEntries = state.OwnedEntries, state.ForeignEntries
		entry.HigherPrecedence = append([]string(nil), state.HigherPrecedence...)
		entry.Conflicts = append([]string(nil), state.Conflicts...)
		result.MachinePolicy[name] = entry
		coverage[name] = entry.HooksInstalled()
	}
	if len(unread) > 0 {
		detail := "it was not inspected"
		if err != nil {
			detail = err.Error()
		}
		result.AddWarning(enterprisestatus.CodeStatusDetailUnavailable, fmt.Sprintf("machine_policy: the vendor machine policy of %s "+
			"could not be read (%s), so its owned_entries and foreign_entries are not reported", strings.Join(unread, ", "), detail))
	}
	return coverage
}

// inspectWindowsEnterpriseMachinePolicy is the read-only machine policy
// inspection of the installed standalone config, with the options the
// guardian publishes from.
func inspectWindowsEnterpriseMachinePolicy(installed *config.Config, names []string) (map[string]enterprisestatus.MachinePolicyState, error) {
	opts, _, standalone, err := standaloneGuardianOptionsFor(installed)
	if err != nil {
		return nil, err
	}
	if !standalone {
		return nil, errors.New("the installed config is not a standalone deployment's")
	}
	return windowsEnterpriseMachinePolicyStates(opts, names)
}

// windowsEnterpriseMachinePolicyStates verifies each connector on its own,
// so one unreadable policy leaves the others reported; a connector whose
// inspection failed is left out.
func windowsEnterpriseMachinePolicyStates(opts enterprisepolicy.Options, names []string) (map[string]enterprisestatus.MachinePolicyState, error) {
	states := make(map[string]enterprisestatus.MachinePolicyState, len(names))
	var errs []error
	for _, name := range names {
		verified, err := enterprisepolicy.VerifyAll(opts, []string{name})
		if err != nil {
			errs = append(errs, err)
			continue
		}
		for _, state := range verified.States {
			if state.Connector == name && state.Route == enterprisepolicy.RouteMachinePolicy {
				states[name] = state.ToStatus()
			}
		}
	}
	return states, errors.Join(errs...)
}
