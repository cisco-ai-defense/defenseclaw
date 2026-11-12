// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import "strings"

// windowsEnterpriseEnsurePlan is the action ensure selected and why.
type windowsEnterpriseEnsurePlan struct {
	Action string // "", install, upgrade, repair
	Reason string
	Detail string // the failed read-only check behind a verify_failed repair
}

// windowsEnterpriseGenerationRecoveryDetail names why ensure repaired a
// compliant deployment after it recovered the config generation record.
const windowsEnterpriseGenerationRecoveryDetail = "config generation record required recovery"

// planWindowsEnterpriseEnsureAfterGenerationRecovery selects ensure's action
// after it recovered a damaged config generation record from the approved
// config. The recovery rewrites only that record, so the deployment still
// gets the action the planner selects: a newer Setup over an older release
// upgrades, and drift is reapplied. Forcing a repair instead kept this
// run's payload as if it were the installed release, put the newer binaries
// in place and recorded the older version. Only a deployment the planner
// finds compliant (the same release and no drift, so this run's payload is
// the installed one) gets the repair that restarts the gateway on the
// recovered record. A planner refusal stays a refusal.
func planWindowsEnterpriseEnsureAfterGenerationRecovery(plan func() (windowsEnterpriseEnsurePlan, error)) (windowsEnterpriseEnsurePlan, error) {
	planned, err := plan()
	if err != nil {
		return windowsEnterpriseEnsurePlan{}, err
	}
	if planned.Action != "" {
		return planned, nil
	}
	return windowsEnterpriseEnsurePlan{Action: "repair", Reason: "verify_failed", Detail: windowsEnterpriseGenerationRecoveryDetail}, nil
}

// windowsEnterpriseCodexTargetTransactionReason is how the ensure result
// says why a config change ran the lifecycle transaction.
const windowsEnterpriseCodexTargetTransactionReason = "the config turns Codex protection on or off, or its Codex target differs from the protected deployment record, and only the lifecycle transaction installs and removes Codex's machine policy"

// windowsEnterpriseConfigRestartCode is the ensure warning of a
// configuration change that ran the lifecycle transaction on the installed
// release. That transaction is the upgrade transaction with this run's
// payload, which is the installed release's own (the planner found the same
// version), so nothing is upgraded; it is used because the services read the
// changed keys only at start, or the running deployment could not take the
// change. The warning used to be ensure_upgrade, which administrators read
// as a package upgrade in MDM results (GAP-0044). A change of only the
// guardian-rendered machine policy keys gets the same code from the hot
// path, which restarts only the hook guardian and the gateway
// (windowsEnterpriseGuardianRestartWarning).
const windowsEnterpriseConfigRestartCode = "ensure_config_restart"

// windowsEnterpriseGuardianRestartWarning is the ensure warning of a
// configuration change the hot path applied by restarting only the hook
// guardian and then the gateway (GAP-0044).
func windowsEnterpriseGuardianRestartWarning(installedVersion string, startOnlyKeys []string) (code, message string) {
	release := "the installed release"
	if version := strings.TrimSpace(installedVersion); version != "" {
		release += " " + version
	}
	return windowsEnterpriseConfigRestartCode, "ensure applied a configuration change (drift:config) to " + release +
		" and upgraded nothing: the services read " + strings.Join(startOnlyKeys, ", ") +
		" only at start, so ensure restarted the hook guardian and then the gateway on the new config; the other services kept running"
}

// windowsEnterpriseConfigFailedCode replaces it when that transaction did
// not succeed: the change is then not known to be applied, and MDM
// remediation (Remediate-Fix.ps1) must not name a repair as the problem.
const windowsEnterpriseConfigFailedCode = "ensure_config_failed"

// windowsEnterpriseConfigDriftReason reports a plan reason that is a changed
// administrator input on the installed release (config.yaml, a policy
// bundle, the Codex target or a guardian manifest), not a changed payload
// file.
func windowsEnterpriseConfigDriftReason(reason string) bool {
	switch reason {
	case "drift:config", "drift:bundle", "drift:codex_target", "drift:manifest":
		return true
	}
	return false
}

// windowsEnterpriseEnsureActionWarning is the warning that names the action
// ensure ran and why. startOnlyKeys are the changed keys the services read
// only at start (GAP-0719); codexTransaction is a change of Codex protection,
// which only the transaction applies (GAP-0033). succeeded is false when the
// run ends with errors (a failed or rolled-back transaction): a configuration
// change is then not reported as applied.
func windowsEnterpriseEnsureActionWarning(plan windowsEnterpriseEnsurePlan, installedVersion string, startOnlyKeys []string, codexTransaction, succeeded bool) (code, message string) {
	why := ""
	switch {
	case len(startOnlyKeys) > 0:
		why = "the services read " + strings.Join(startOnlyKeys, ", ") + " only at start"
	case codexTransaction:
		why = windowsEnterpriseCodexTargetTransactionReason
	}
	if plan.Action == "upgrade" && windowsEnterpriseConfigDriftReason(plan.Reason) {
		if why == "" {
			why = "the change could not be applied in the running deployment"
			if plan.Reason == "drift:manifest" {
				why = "only the lifecycle transaction installs a supplied guardian manifest"
			}
		}
		release := "the installed release"
		if version := strings.TrimSpace(installedVersion); version != "" {
			release += " " + version
		}
		if !succeeded {
			return windowsEnterpriseConfigFailedCode, "ensure ran the lifecycle transaction for a configuration change (" + plan.Reason + ") on " + release +
				" and upgraded nothing, but the transaction did not succeed, so the change is not confirmed applied: see the errors"
		}
		return windowsEnterpriseConfigRestartCode, "ensure applied a configuration change (" + plan.Reason + ") to " + release +
			" and upgraded nothing: " + why + ", so ensure ran the lifecycle transaction on the same release, which stops and starts every service and verifies the deployment (two to six minutes)"
	}
	reason := plan.Reason
	if why != "" {
		reason += " (" + why + ", so every service was restarted)"
	}
	if plan.Detail != "" && (plan.Reason == "verify_failed" || plan.Reason == "drift:cowork_vm_sensor") {
		reason += ": " + plan.Detail
	}
	return "ensure_" + plan.Action, "ensure ran " + plan.Action + ": " + reason
}
