// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
)

// windowsEnterpriseGuardianRepairPendingCode is the warning of a target the
// standalone Windows guardian has not verified as protected: its last pass
// failed on it, or one of its hook files is gone since. Linux and macOS use
// the same code for a hook file changed since the guardian's pass.
const windowsEnterpriseGuardianRepairPendingCode = "guardian_repair_pending"

// applyWindowsEnterpriseGuardianTargetGaps clears security_complete for each
// enrolled target the guardian's last pass (state) did not leave protected,
// and for each target whose recorded hook file is absent now (ownedFiles
// lists the files to look for). Status and verify said the host was
// security-complete, or gave only the guardian's lifecycle error, while such
// a target's hook file was deleted (GAP-0146), so each of these targets also
// gets a guardian_repair_pending warning that names the account and the
// agent:
//   - a row that waits for its signed-out account's next sign-in;
//   - a row the guardian could not repair because its account has no active
//     Windows session (signed out, or a disconnected session): the guardian
//     repairs only in that session;
//   - a row with a hook file that is absent now (a verified row since the
//     pass, or a failed row).
//
// Any other failed row already fails the guardian status, which names it. A
// row of a removed account protects no one and is left to the enumerator,
// and a pending row was never enrolled.
func applyWindowsEnterpriseGuardianTargetGaps(
	result *enterprisestatus.Result,
	state enterpriseHookGuardianState,
	ownedFiles func(enterpriseHookReconcileRow) []string,
) {
	for _, row := range state.Results {
		if row.Pending || (!row.OK && enterpriseHookRemovedAccountRow(row)) {
			continue
		}
		connector := strings.TrimSpace(row.Connector)
		account := windowsEnterpriseGuardianRowAccount(row)
		missing := windowsEnterpriseGuardianMissingHookFiles(row, ownedFiles)
		var reason string
		if !row.OK {
			result.SecurityComplete = false
			switch {
			case enterpriseHookEarlierMatrixRow(row):
				reason = fmt.Sprintf(
					"%s for %s runs the hooks an earlier DefenseClaw release registered: it is guarded, but a hook "+
						"spawn error or timeout does not block until the guardian upgrades them in that account's own "+
						"Windows session at its next connect", connector, account)
			case enterpriseHookAwaitingSignInError(row):
				reason = fmt.Sprintf(
					"the hook guardian's last pass could not verify %s for %s, and it repairs it only in that account's "+
						"own Windows session; that agent's hook calls may not be inspected until the account signs in "+
						"and the guardian repairs it", connector, account)
			case enterpriseHookSessionUnavailable(row.Error):
				reason = fmt.Sprintf(
					"the hook guardian's last pass could not verify %s for %s, and it cannot repair it while that "+
						"account is signed out or its session is disconnected: it repairs DefenseClaw hooks only in the "+
						"account's own active Windows session; that agent's hook calls may not be inspected until the "+
						"account signs in or reconnects and the guardian repairs it", connector, account)
			}
		}
		if reason == "" && len(missing) == 0 {
			continue
		}
		result.SecurityComplete = false
		message := reason
		switch {
		case reason != "" && len(missing) > 0:
			message = fmt.Sprintf("%s (missing: %s)", reason, strings.Join(missing, ", "))
		case row.OK:
			message = fmt.Sprintf(
				"%d DefenseClaw hook file(s) of %s for %s are missing since the hook guardian last verified them (%s); "+
					"that agent's hook calls may not be inspected until the guardian puts them back on its next pass",
				len(missing), account, connector, strings.Join(missing, ", "))
		case reason == "":
			message = fmt.Sprintf(
				"%d DefenseClaw hook file(s) of %s for %s are missing and the hook guardian's last pass failed on that "+
					"target (%s); that agent's hook calls may not be inspected until the guardian repairs it",
				len(missing), account, connector, strings.Join(missing, ", "))
		}
		result.AddWarning(windowsEnterpriseGuardianRepairPendingCode, message)
	}
}

// windowsEnterpriseGuardianMissingHookFiles lists the hook files of row
// (ownedFiles) that do not exist now. Only "does not exist" counts: any other
// error leaves the guardian as the verifier, because the caller's token may
// not read every profile.
func windowsEnterpriseGuardianMissingHookFiles(
	row enterpriseHookReconcileRow,
	ownedFiles func(enterpriseHookReconcileRow) []string,
) []string {
	if ownedFiles == nil {
		return nil
	}
	var missing []string
	for _, path := range ownedFiles(row) {
		if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
			missing = append(missing, path)
		}
	}
	return missing
}

// enterpriseHookSessionUnavailable matches the two errors a protected
// Windows target records while its account has no active Windows session
// (signed out, or a disconnected session).
func enterpriseHookSessionUnavailable(message string) bool {
	return strings.Contains(message, "exact active Windows session is unavailable") ||
		strings.Contains(message, "no active interactive session token matches")
}

// applyWindowsEnterpriseGuardianTargetsFrom applies the guardian's last pass
// (loadState) to status and verify, with the hook files of each verified
// target. Status and verify run without a loaded config (the enterprise
// windows commands skip the config load), so the Copilot VS Code Local hook
// file is decided from the installed config (loadInstalled), not from the
// process's own: the guardian writes it from that file, and with the
// process's config the check never listed it, so a deleted file left status
// security-complete (GAP-0146). An unreadable or missing guardian state is
// left to the guardian status, which fails on it.
func applyWindowsEnterpriseGuardianTargetsFrom(
	result *enterprisestatus.Result,
	loadState func() (enterpriseHookGuardianState, bool, error),
	loadInstalled func() (*config.Config, error),
) {
	state, exists, err := loadState()
	if err != nil || !exists {
		return
	}
	copilotHookFile := windowsEnterpriseCopilotVSCodeHookFileWantedBy(loadInstalled())
	applyWindowsEnterpriseGuardianTargetGaps(result, state, windowsEnterpriseGuardianTargetHookFiles(copilotHookFile))
}

// windowsEnterpriseCopilotVSCodeHookFileWantedBy reports whether the
// guardian writes each Copilot target's VS Code Local hook file under
// installed, with the options the guardian builds from it. A config that
// cannot be read or resolved counts as wanted (fail closed): a verified
// Copilot target's absent file is then reported, not passed.
func windowsEnterpriseCopilotVSCodeHookFileWantedBy(installed *config.Config, loadErr error) bool {
	if loadErr != nil {
		return true
	}
	opts, _, standalone, err := standaloneGuardianOptionsFor(installed)
	if !standalone || err != nil {
		return true
	}
	hookFile, _ := enterprisepolicy.CopilotVSCodeUserWant(opts)
	return hookFile
}

// windowsEnterpriseGuardianTargetHookFiles lists, for each verified row, the
// hook files status and verify look for: those the guardian recorded, and a
// Copilot row's VS Code Local hook file when copilotVSCodeHookFile.
func windowsEnterpriseGuardianTargetHookFiles(copilotVSCodeHookFile bool) func(enterpriseHookReconcileRow) []string {
	return func(row enterpriseHookReconcileRow) []string {
		var extra []string
		home := strings.TrimSpace(row.UserHome)
		if copilotVSCodeHookFile && home != "" &&
			strings.EqualFold(strings.TrimSpace(row.Connector), enterprisepolicy.ConnectorCopilot) {
			extra = []string{enterprisepolicy.CopilotVSCodeLocalHookFilePath(home)}
		}
		return windowsEnterpriseGuardianRowHookFiles(row, extra)
	}
}

// standaloneGuardianOptionsFor is the standalone guardian's machine policy
// options and connectors for current; standalone is false when current is
// not a standalone deployment's config.
func standaloneGuardianOptionsFor(current *config.Config) (opts enterprisepolicy.Options, connectors []string, standalone bool, err error) {
	if current == nil || !current.StandaloneEnterprise() {
		return enterprisepolicy.Options{}, nil, false, nil
	}
	layout, programFiles, programData, err := standaloneEnterprisePolicyLayout()
	if err != nil {
		return enterprisepolicy.Options{}, nil, true, err
	}
	opts, err = enterprisepolicy.StandaloneOptions(layout, programFiles, programData, current)
	if err != nil {
		return enterprisepolicy.Options{}, nil, true, err
	}
	opts.ClaudeMachineHookContract = standaloneClaudeMachineHookContract(layout)
	return opts, enterprisepolicy.StandaloneConnectors(current), true, nil
}

// windowsEnterpriseGuardianRowAccount names a guardian row's account: user,
// else profile folder, else SID.
func windowsEnterpriseGuardianRowAccount(row enterpriseHookReconcileRow) string {
	for _, value := range []string{row.User, row.UserHome, row.SID} {
		if value = strings.TrimSpace(value); value != "" {
			return value
		}
	}
	return "an enrolled account"
}

// windowsEnterpriseGuardianRowHookFiles lists the hook config files the
// guardian recorded for a verified row, plus extra (files the guardian writes
// for the row beyond them), each once.
func windowsEnterpriseGuardianRowHookFiles(row enterpriseHookReconcileRow, extra []string) []string {
	seen := map[string]struct{}{}
	var out []string
	add := func(path string) {
		path = strings.TrimSpace(path)
		if path == "" {
			return
		}
		path = filepath.Clean(path)
		if _, ok := seen[path]; ok {
			return
		}
		seen[path] = struct{}{}
		out = append(out, path)
	}
	if row.Result != nil {
		for _, path := range row.Result.HookConfigPaths {
			add(path)
		}
	}
	for _, path := range extra {
		add(path)
	}
	sort.Strings(out)
	return out
}
