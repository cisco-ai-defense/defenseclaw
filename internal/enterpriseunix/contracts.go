// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// codeHookContractUnverified names a guardian target whose agent version
// has no verified DefenseClaw hook contract. The guardian refuses to
// install hooks it cannot parse or enforce, so that agent runs without
// DefenseClaw until an administrator acts.
const codeHookContractUnverified = "hook_contract_unverified"

// codeGuardianTargetFailed names any other guardian target the guardian
// could not protect.
const codeGuardianTargetFailed = "guardian_target_failed"

// codeGuardianTargetAccountRemoved names a guardian target whose account
// the guardian's directory lookup definitively reports as gone, typically a
// deleted account whose target the enumerator has not revoked yet. It is a
// warning: verify, MDM detection and security_complete do not fail on it.
const codeGuardianTargetAccountRemoved = "guardian_target_account_removed"

// codeGuardianTargetUserPath names a guardian target the guardian refused
// because of a path in that account's own home: a symbolic link, a file
// where a folder belongs (or a folder where a file belongs), a folder the
// account made unreadable, or the agent's own config folder the account has
// not created yet, or its config file (it has not set the agent up,
// GAP-2593). Only that account
// is affected, and it could have
// made the change itself, so it is a warning: verify, MDM detection and
// security_complete do not fail on it. The guardian protects the target
// again at its next reconcile after the path is fixed.
const codeGuardianTargetUserPath = "guardian_target_user_path"

// guardianStateFile is the guardian state the gateway reads in DataDir.
const guardianStateFile = "hook_guardian_state.json"

// enumeratorStateFile is the hook enumerator's state beside targets.yaml:
// its definitive misses per target and the source of each account.
const enumeratorStateFile = ".targets-enumerator-state.json"

var unverifiedVersionPattern = regexp.MustCompile(`agent version "([^"]*)"`)

// describeHookContracts reports every guardian target the guardian could
// not protect (an unverified hook contract gets its own code) and marks the
// deployment security-incomplete: an unprotected agent must never look like
// a healthy deployment. A target with no verified hook contract also marks
// coverage incomplete: no DefenseClaw hook is installed for it. A target refused only because of a path in its
// account's own home is reported for that account without marking the
// deployment incomplete.
func (l *lifecycle) describeHookContracts(ctx context.Context) {
	env, r := l.env, l.result
	// The guardian state is in DataDir, which the service account can
	// replace, so a failure the root-only attestation reports is named even
	// when that state leaves it out or reports it protected. The guardian
	// writes the ledger, then the state, then the attestation, so a state
	// read between one reconcile's ledger and the next one's is from the
	// attestation's reconcile.
	ledgerPath := env.P(filepath.Join(env.Layout.GuardianAuthDir, managed.HookGuardianAuthorizationFile))
	ledger, _ := readBounded(ledgerPath, 4<<20)
	attestation, err := env.readAttestation()
	attested := err == nil && attestation.BoundTo(ledger)
	var state struct {
		Results []struct {
			User      string `json:"user"`
			UserHome  string `json:"user_home"`
			Connector string `json:"connector"`
			OK        bool   `json:"ok"`
			Error     string `json:"error"`
		} `json:"results"`
	}
	if data, err := readBounded(env.P(filepath.Join(env.Layout.DataDir, guardianStateFile)), 4<<20); err == nil {
		_ = json.Unmarshal(data, &state)
	}
	if again, err := readBounded(ledgerPath, 4<<20); err != nil || !bytes.Equal(again, ledger) {
		attested = false
	}
	var unverified, failed, removed, userPaths []string
	stateFailed := map[string]bool{}
	enumeration := enterprisehooks.LoadUnixEnumeratorState(env.P(filepath.Join(filepath.Dir(env.Layout.ManifestPath), enumeratorStateFile)))
	for _, result := range state.Results {
		if result.OK || strings.TrimSpace(result.Error) == "" {
			continue
		}
		stateFailed[enterprisehooks.CredentialAttestationTarget{Connector: result.Connector, User: result.User, UserHome: result.UserHome}.Key()] = true
		if (targetAccountMissingError(result.Error) || targetHomeUnavailableError(result.Error)) && l.accountAbsent(ctx, result.User) {
			// An account that does not resolve, or whose home went with it, is
			// not a protection failure.
			// Say it is gone only when the enumerator confirmed it: a directory
			// that does not answer gives the same "no such account", and then
			// directory_lookups_failing says so and the target stays (GAP-0593).
			// Even then it says the account does not resolve, not that it
			// was deleted: while the directory is unreachable the lookup
			// gives the same answer (GAP-0838).
			if enterprisehooks.UnixMissConfirmed(enumeration, result.User, result.Connector) {
				message := fmt.Sprintf("%s for user %s: the account does not resolve (the lookup answers \"no such account\"); "+
					"if it was deleted, the enumerator removes this target after %d consecutive definitive misses, one per "+
					"enumeration cycle; while the directory does not answer, nothing is removed",
					result.Connector, result.User, enterprisehooks.UnixRevokeAfterMisses)
				if directoryLookupsFailing(r.Warnings) {
					message = fmt.Sprintf("%s for user %s: the account does not resolve while directory lookups are failing, "+
						"so DefenseClaw cannot tell whether it was deleted; the target stays until the directory answers",
						result.Connector, result.User)
				}
				removed = append(removed, message)
			} else if !directoryLookupsFailing(r.Warnings) {
				// A miss the enumerator has not confirmed, with no directory
				// outage to explain it, is a target the guardian could not
				// protect: it stays and is reported (GAP-1133).
				failed = append(failed, fmt.Sprintf("%s for user %s is not protected: the guardian's last reconcile could not "+
					"resolve the account, and the enumerator has not confirmed that it is gone; the guardian protects it again "+
					"once the account resolves", result.Connector, result.User))
			}
			continue
		}
		if !unverifiedHookContractError(result.Error) {
			reason := strings.TrimSpace(strings.TrimPrefix(result.Error, "enterprise hooks: "))
			message := fmt.Sprintf("%s for user %s is not protected: %s", result.Connector, result.User, boundedGuardianReason(reason))
			if userHomePathRefusal(reason, result.UserHome) {
				userPaths = append(userPaths, message+"; the path is in that account's own home, so only that account is affected; the guardian protects it again once the path is fixed")
				continue
			}
			failed = append(failed, message)
			continue
		}
		version := "unknown"
		if match := unverifiedVersionPattern.FindStringSubmatch(result.Error); match != nil && match[1] != "" {
			version = match[1]
		}
		unverified = append(unverified, fmt.Sprintf(
			"%s %s for user %s has no verified DefenseClaw hook contract, so it runs without DefenseClaw hooks; pin a verified agent version or add a verified hook contract",
			result.Connector, version, result.User))
	}
	if attested {
		for _, target := range attestation.Targets {
			if target.State == enterprisehooks.CredentialTargetFailed && !stateFailed[target.Key()] {
				failed = append(failed, fmt.Sprintf("%s is not protected: the guardian's last reconcile failed it, and the guardian state does not say why; see the hook guardian's log", target.Label()))
			}
		}
	}
	sort.Strings(removed)
	for _, message := range removed {
		r.AddWarning(codeGuardianTargetAccountRemoved, message)
	}
	sort.Strings(userPaths)
	for _, message := range userPaths {
		r.AddWarning(codeGuardianTargetUserPath, message)
	}
	for _, message := range l.agentConfigNotices() {
		r.AddWarning(codeAgentSettingsNotRestored, message)
	}
	if len(unverified)+len(failed) == 0 {
		return
	}
	sort.Strings(unverified)
	sort.Strings(failed)
	for _, message := range unverified {
		r.AddWarning(codeHookContractUnverified, message)
	}
	for _, message := range failed {
		r.AddWarning(codeGuardianTargetFailed, message)
	}
	if len(failed) > 0 {
		r.MarkSecurityIncomplete(codeGuardianTargetFailed)
	}
	if len(unverified) > 0 {
		// An enrolled agent with no hook contract has no DefenseClaw hook at
		// all, so the deployment does not cover it (GAP-0151).
		r.MarkCoverageIncomplete(codeHookContractUnverified)
	}
}

// requireProtectedTargets fails an install, upgrade, repair or ensure that
// leaves an enrolled target unprotected: each guardian_target_failed warning
// describe reported becomes an error with the same cause, as verify and
// reconcile already fail on it. The change itself stays committed. An
// ensure on a managed host whose enrolled Hermes the guardian could not
// verify returned ok and exit 0 next to security_complete false (GAP-0846).
// A target refused for a path in its own account's home, the target of an
// account that is gone and an agent version with no verified hook contract
// stay warnings here, as in verify. It returns code.
func (l *lifecycle) requireProtectedTargets(code int) int {
	r := l.result
	failed := map[string]bool{}
	for _, message := range r.Errors {
		if message.Code == codeGuardianTargetFailed {
			failed[message.Message] = true
		}
	}
	for _, warning := range r.Warnings {
		if warning.Code != codeGuardianTargetFailed || failed[warning.Message] {
			continue
		}
		failed[warning.Message] = true
		r.AddError(codeGuardianTargetFailed, warning.Message+"; the change was applied, but DefenseClaw does not protect that agent: fix the cause, then run `"+
			l.env.lifecycleCommand(ActionReconcile)+"` (the guardian also retries every minute) and `"+l.env.lifecycleCommand(ActionVerify)+"`")
	}
	if len(failed) > 0 {
		r.MarkSecurityIncomplete(codeGuardianTargetFailed)
	}
	return code
}

// requireProtectedTargetsOnChange is requireProtectedTargets for a run that
// ends before its action does anything: an empty bundle inbox, a bundle
// mode refusal, or a queued apply run that stands down. Such an ensure
// (or install, upgrade, repair) exited 0 while describe reported an
// enrolled target unprotected (GAP-0985). Other actions return code as it
// is.
func (l *lifecycle) requireProtectedTargetsOnChange(code int) int {
	switch l.opts.Action {
	case ActionInstall, ActionUpgrade, ActionRepair, ActionEnsure:
		return l.requireProtectedTargets(code)
	}
	return code
}

// codeAgentSettingsNotRestored names an account whose agent config the
// guardian had to recreate or put back from a copy (GAP-0564): the hooks are
// in place, but the account's own settings are missing or older.
const codeAgentSettingsNotRestored = "agent_settings_not_restored"

// guardianNoticesFile is the guardian's record of the protected targets
// whose agent config its last reconcile put back from a copy or recreated
// (hookGuardianNoticesFile in internal/cli).
const guardianNoticesFile = "hook_guardian_notices.json"

// agentConfigNotices words the guardian's agent config notices, one per
// account and connector, sorted. A protected target whose agent config lost
// the account's own settings is that account's to fix: a warning, not a
// protection failure. Only the known codes are worded: the per-user worker
// that reports them runs as the account.
func (l *lifecycle) agentConfigNotices() []string {
	data, err := readBounded(l.env.P(filepath.Join(l.env.Layout.DataDir, guardianNoticesFile)), 1<<20)
	if err != nil {
		return nil
	}
	var record struct {
		Version int `json:"version"`
		Targets []struct {
			User        string `json:"user"`
			Connector   string `json:"connector"`
			AgentConfig string `json:"agent_config"`
		} `json:"targets"`
	}
	if json.Unmarshal(data, &record) != nil || record.Version != 1 {
		return nil
	}
	var out []string
	for _, target := range record.Targets {
		if message, ok := connector.AgentConfigNotice(target.Connector, boundedGuardianReason(target.User), target.AgentConfig); ok {
			out = append(out, message)
		}
	}
	sort.Strings(out)
	return out
}

// codeGuardianReportPending names a change whose guardian report did not
// arrive in time.
const codeGuardianReportPending = "guardian_report_pending"

// awaitGuardianReport waits, bounded by GuardianReportTimeout, for the
// guardian to publish its target report after since (the restarted guardian
// reconciles every manifest target under the new config), so the result of
// the change names the targets it left unprotected, for example an agent
// version without a verified hook contract in the new guardrail mode.
// Without manifest targets it still waits: the guardian writes that report
// after its authorization ledger, and until the ledger exists the result
// reads the guardian as not ready. It reports whether the report arrived.
func (l *lifecycle) awaitGuardianReport(ctx context.Context, since time.Time) bool {
	env, r := l.env, l.result
	targets := 0
	if manifest, err := enterprisehooks.LoadStandaloneManifest(env.P(env.Layout.ManifestPath)); err == nil {
		targets = len(manifest.Targets)
	}
	deadline := env.Now().Add(env.GuardianReportTimeout)
	for {
		if updated, ok := l.guardianReportedAt(); ok && !updated.Before(since) {
			return true
		}
		if !env.Now().Before(deadline) {
			if targets > 0 {
				r.AddWarning(codeGuardianReportPending, fmt.Sprintf(
					"the hook guardian has not reported on its %d manifest targets since this change, so their protection is not confirmed yet; run `%s` in a minute to see it",
					targets, env.lifecycleCommand("status")))
			}
			return false
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(env.PollInterval):
		}
	}
}

// guardianRepairsFile is the guardian's record of the targets its last
// reconcile rewrote (hookGuardianRepairsFile in internal/cli).
const guardianRepairsFile = "hook_guardian_repairs.json"

// noteRepairedTargets lists, as changes, the per-account targets whose
// hooks the guardian rewrote at or after since because they no longer
// matched (a hook script or config entry changed or removed).
func (l *lifecycle) noteRepairedTargets(since time.Time) {
	data, err := readBounded(l.env.P(filepath.Join(l.env.Layout.DataDir, guardianRepairsFile)), 4<<20)
	if err != nil {
		return
	}
	var record struct {
		UpdatedAt string `json:"updated_at"`
		Repaired  []struct {
			User      string `json:"user"`
			Connector string `json:"connector"`
		} `json:"repaired"`
	}
	if json.Unmarshal(data, &record) != nil {
		return
	}
	if updated, err := time.Parse(time.RFC3339Nano, record.UpdatedAt); err != nil || updated.Before(since) {
		return
	}
	for _, target := range record.Repaired {
		l.noteChange("rewrote the %s hooks of user %s", target.Connector, target.User)
	}
}

// guardianReportedAt is when the guardian last wrote its target report.
func (l *lifecycle) guardianReportedAt() (time.Time, bool) {
	env := l.env
	data, err := readBounded(env.P(filepath.Join(env.Layout.DataDir, guardianStateFile)), 4<<20)
	if err != nil {
		return time.Time{}, false
	}
	var state struct {
		UpdatedAt string `json:"updated_at"`
	}
	if json.Unmarshal(data, &state) != nil {
		return time.Time{}, false
	}
	updated, err := time.Parse(time.RFC3339Nano, state.UpdatedAt)
	return updated, err == nil
}

// guardianActivationFile is the guardian's activation receipt in
// GuardianAuthDir (hookGuardianActivationFile in internal/cli): the last
// file a guardian reconcile writes, after its target report.
const guardianActivationFile = "activation.json"

// guardianTargetFailedSince reports whether a guardian reconcile finished
// writing its report at or after since and could not protect a target.
func (l *lifecycle) guardianTargetFailedSince(since time.Time) bool {
	env := l.env
	data, err := readBounded(env.P(filepath.Join(env.Layout.GuardianAuthDir, guardianActivationFile)), 4<<20)
	if err != nil {
		return false
	}
	var activation struct {
		UpdatedAt    string `json:"updated_at"`
		FailureCount int    `json:"failure_count"`
	}
	if json.Unmarshal(data, &activation) != nil {
		return false
	}
	updated, err := time.Parse(time.RFC3339Nano, activation.UpdatedAt)
	return err == nil && !updated.Before(since) && activation.FailureCount > 0
}

// codeAgentUnprotected names an agent the enumerator found installed for an
// eligible user but could not enroll; it runs without DefenseClaw hooks.
const codeAgentUnprotected = enterprisehooks.UnprotectedCodeAgentUnprotected

// reportInstallScanPending reports a missing or stale unprotected-agents
// record, or one an earlier install wrote, as one NOT COVERED warning, verify included (GAP-1430). Only that
// condition is a warning: every other check, and every agent a stale record
// names, keeps its own verdict.
func (l *lifecycle) reportInstallScanPending(age string) {
	remedy := "sudo systemctl restart " + unitEnumerator
	if l.env.GOOS == "darwin" {
		remedy = "sudo launchctl kickstart -k system/" + labelEnumerator
	}
	l.result.AddWarning(enterprisehooks.UnprotectedCodeInstallScanIncomplete, enterprisehooks.UnprotectedAgentsScanPending(age, remedy))
	l.result.MarkCoverageIncomplete(enterprisehooks.UnprotectedCodeInstallScanIncomplete)
}

// describeUnprotectedAgents reports the agents the enumerator found
// uncovered (its unprotected-agents record next to the
// manifest) and marks the deployment security-incomplete. Each is one
// account's agent, so it is a warning for that account, verify included; an
// unreadable record hides which agents they are, so verify fails on it, as
// on an app or extension surface enterprise.enrollment.unverified_versions:
// refuse could not refuse.
func (l *lifecycle) describeUnprotectedAgents() {
	env, r := l.env, l.result
	data, err := readBounded(env.P(enterprisehooks.UnprotectedAgentsPath(env.Layout.ManifestPath)), enterprisehooks.UnprotectedAgentsMaxBytes)
	if errors.Is(err, os.ErrNotExist) {
		l.reportInstallScanPending(enterprisehooks.UnprotectedAgentsRecordMissing)
		return
	}
	if err != nil {
		message := "the enumerator's unprotected-agents record is missing or unreadable: " + err.Error()
		if l.opts.Action == ActionVerify {
			r.AddError(enterprisehooks.UnprotectedCodeInstallScanIncomplete, message)
		} else {
			r.AddWarning(enterprisehooks.UnprotectedCodeInstallScanIncomplete, message)
		}
		r.MarkCoverageIncomplete(enterprisehooks.UnprotectedCodeInstallScanIncomplete)
		return
	}
	agents, err := enterprisehooks.ParseUnprotectedAgents(data)
	if err != nil {
		message := "the enumerator's unprotected-agents record is unreadable: " + err.Error()
		if l.opts.Action == ActionVerify {
			r.AddError(enterprisehooks.UnprotectedCodeInstallScanIncomplete, message)
		} else {
			r.AddWarning(enterprisehooks.UnprotectedCodeInstallScanIncomplete, message)
		}
		r.MarkCoverageIncomplete(enterprisehooks.UnprotectedCodeInstallScanIncomplete)
		return
	}
	info, err := os.Stat(env.P(enterprisehooks.UnprotectedAgentsPath(env.Layout.ManifestPath)))
	if err != nil {
		message := "the enumerator's unprotected-agents record's scan time cannot be read: " + err.Error()
		if l.opts.Action == ActionVerify {
			r.AddError(enterprisehooks.UnprotectedCodeInstallScanIncomplete, message)
		} else {
			r.AddWarning(enterprisehooks.UnprotectedCodeInstallScanIncomplete, message)
		}
		r.MarkCoverageIncomplete(enterprisehooks.UnprotectedCodeInstallScanIncomplete)
	} else if now := time.Now(); enterprisehooks.UnprotectedAgentsRecordStale(info.ModTime(), now) {
		l.reportInstallScanPending(enterprisehooks.UnprotectedAgentsRecordAge(info.ModTime(), now))
	} else if written := enterprisehooks.UnprotectedAgentsRecordGeneration(data); written != enterprisehooks.UnprotectedAgentsGeneration() {
		// A recent record of the previous install is not this install's
		// scan (GAP-1454): pending until the current enumerator publishes.
		l.reportInstallScanPending(enterprisehooks.UnprotectedAgentsRecordFromEarlierInstall(written))
	}
	for _, agent := range agents {
		if agent.Code == enterprisehooks.UnprotectedCodeHookContractUnverified ||
			agent.Code == enterprisehooks.UnprotectedCodeInstallScanIncomplete ||
			agent.Code == enterprisehooks.UnprotectedCodeKiroCLIBelowHookFloor ||
			agent.Code == enterprisehooks.UnprotectedCodeKiroIDEBelowGlobalHooksFloor {
			// No contract, an incomplete install scan, a headless CLI path
			// without hooks, or an IDE that cannot read global hooks: the
			// deployment does not cover it (GAP-0151).
			r.MarkCoverageIncomplete(agent.Code)
		}
		if l.opts.Action == ActionVerify && (agent.Refusal == enterprisehooks.RefusalMissing ||
			agent.Code == enterprisehooks.UnprotectedCodeKiroCLIBelowHookFloor ||
			agent.Code == enterprisehooks.UnprotectedCodeKiroIDEBelowGlobalHooksFloor) {
			r.AddError(agent.Code, agent.Message())
			continue
		}
		r.AddWarning(agent.Code, agent.Message())
		if agent.InstallPath != "" && (l.opts.Action == ActionStatus || l.opts.Action == ActionVerify) && env.ReportLaunchCoverage != nil && agent.UID != nil {
			reason := "unsupported_installed_version"
			if agent.Version == "" {
				reason = "installed_version_unverified"
			}
			if err := env.ReportLaunchCoverage(context.Background(), managed.LaunchCoverageReport{
				Connector: agent.Connector, Reason: reason, UID: *agent.UID,
				InstallPath: agent.InstallPath, Version: agent.Version,
			}); err != nil {
				r.AddWarning(codeManagedLaunchAuditUnavailable, "could not audit the unprotected "+agent.Connector+" install: "+err.Error())
			}
		}
	}
	for _, agent := range agents {
		r.MarkSecurityIncomplete(agent.Code)
	}
}

// codeGuardianCleanupPending names a DefenseClaw hook registration the hook
// guardian still has to remove from the home of a user the manifest no
// longer enrolls for that connector (the connector was disabled or removed,
// or the user is no longer enrolled). Until it is removed the gateway
// refuses those hooks, so the user's agent can stop at them. It is a
// warning: verify and security_complete do not fail on it.
const codeGuardianCleanupPending = "guardian_cleanup_pending"

// describeGuardianCleanups reports the entries of the guardian's per-user
// cleanup ledger next to its authorization ledger.
func (l *lifecycle) describeGuardianCleanups() {
	env, r := l.env, l.result
	data, err := readBounded(env.P(filepath.Join(env.Layout.GuardianAuthDir, managed.HookGuardianUserCleanupFile)), 4<<20)
	if err != nil {
		return
	}
	var ledger struct {
		Pending []struct {
			Connector string `json:"connector"`
			User      string `json:"user"`
			UserHome  string `json:"user_home"`
			LastError string `json:"last_error"`
		} `json:"pending"`
	}
	if json.Unmarshal(data, &ledger) != nil {
		return
	}
	for _, entry := range ledger.Pending {
		account := strings.TrimSpace(entry.User)
		if account == "" {
			account = strings.TrimSpace(entry.UserHome)
		}
		// A home that does not answer a bounded lookup keeps the cleanup
		// reported as pending (GAP-1751).
		if home := strings.TrimSpace(entry.UserHome); home != "" && env.homeAnswers(env.P(home)) {
			if _, err := os.Lstat(env.P(home)); errors.Is(err, os.ErrNotExist) {
				// The account may have moved. Keep the guardian's current-home
				// failure visible instead of calling a missing recorded home
				// proof that the account was deleted (GAP-0254).
				message := fmt.Sprintf("%s for user %s: the recorded home %s no longer exists; no hook registration is left there; the hook guardian checks the account's current home before retiring this cleanup",
					entry.Connector, account, home)
				if reason := strings.TrimSpace(entry.LastError); reason != "" {
					message += "; the last cleanup attempt failed and is retried: " + boundedGuardianReason(strings.TrimPrefix(reason, "enterprise hooks: "))
				}
				r.AddWarning(codeGuardianCleanupPending, message)
				continue
			}
		}
		message := fmt.Sprintf("%s for user %s is no longer enrolled, but DefenseClaw's hook registration is still in %s and the gateway refuses its hooks; ",
			entry.Connector, account, entry.UserHome)
		if reason := strings.TrimSpace(entry.LastError); reason != "" {
			message += "the hook guardian's last attempt to remove it as that user failed and is retried: " + boundedGuardianReason(strings.TrimPrefix(reason, "enterprise hooks: "))
		} else {
			message += "the hook guardian removes it as that user once the home is available"
		}
		r.AddWarning(codeGuardianCleanupPending, message)
	}
}

// A missing home cannot establish whether the account was deleted or its
// home is temporarily unavailable. Enrollment is retained for a retry.
const codeEnrolledHomeUnavailable = "enrolled_home_unavailable"

// describeUnavailableEnrolledHomes names enrolled targets whose home cannot
// currently be found. The enumerator decides separately whether an account
// has definitively disappeared.
func (l *lifecycle) describeUnavailableEnrolledHomes() {
	env, r := l.env, l.result
	manifest, err := enterprisehooks.LoadStandaloneManifest(env.P(env.Layout.ManifestPath))
	if err != nil {
		return
	}
	connectors := map[string][]string{}
	var accounts []string
	for _, target := range manifest.Targets {
		home := strings.TrimSpace(target.UserHome)
		if home == "" || (target.Enabled != nil && !*target.Enabled) {
			continue
		}
		// A home that does not answer a bounded lookup is not looked up in
		// this process; describeUnansweredHomes names it (GAP-1751).
		if !env.homeAnswers(env.P(home)) {
			continue
		}
		if _, err := os.Lstat(env.P(home)); !errors.Is(err, os.ErrNotExist) {
			continue
		}
		account := cmp.Or(strings.TrimSpace(target.User), home)
		key := account + " (home " + home + ")"
		if _, seen := connectors[key]; !seen {
			accounts = append(accounts, key)
		}
		connectors[key] = append(connectors[key], strings.TrimSpace(target.Connector))
	}
	sort.Strings(accounts)
	for _, account := range accounts {
		names := connectors[account]
		sort.Strings(names)
		r.AddWarning(codeEnrolledHomeUnavailable, fmt.Sprintf(
			"user %s: home is unavailable; enrollment for %s is retained and retried on the next hook enumerator pass",
			account, strings.Join(names, ", ")))
	}
}

// describeUnansweredHomes names each home whose bounded lookup did not
// answer in this status or verify run. Nothing in it was read: the
// DefenseClaw files, sandboxes and agent settings there are not confirmed,
// so security_complete is false (GAP-1751).
func (l *lifecycle) describeUnansweredHomes() {
	for _, home := range l.env.unansweredHomes() {
		l.result.MarkSecurityIncomplete(codeEnrolledHomeUnavailable)
		l.result.AddWarning(codeEnrolledHomeUnavailable, fmt.Sprintf(
			"home %s did not answer a lookup within %s (a stalled home mount?), so the DefenseClaw files, sandboxes and agent settings in it are not checked in this run; enrollment is retained",
			boundedGuardianReason(home), enterprisestatus.LaunchPathLookupTimeout()))
	}
}

// guardianReasonMaxBytes bounds one guardian target reason in the result.
// Guardian errors name the refused path and end with the remedy after the
// last "; ", so the bound is generous and a longer reason keeps its remedy.
const guardianReasonMaxBytes = 1024

func boundedGuardianReason(reason string) string {
	if len(reason) <= guardianReasonMaxBytes {
		return reason
	}
	if index := strings.LastIndex(reason, "; "); index > 0 && len(reason)-index <= guardianReasonMaxBytes/2 {
		remedy := reason[index:]
		return truncateUTF8(reason[:index], guardianReasonMaxBytes-len(remedy)-len("...")) + "..." + remedy
	}
	return truncateUTF8(reason, guardianReasonMaxBytes-len("...")) + "..."
}

// truncateUTF8 cuts value to at most limit bytes without splitting a rune.
func truncateUTF8(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	for limit > 0 && !utf8.RuneStart(value[limit]) {
		limit--
	}
	return value[:limit]
}

// targetAccountMissingPattern is the whole of the guardian's definitive
// "no such account" resolution error (resolveEnterpriseHookStandaloneAccount
// in internal/cli), with the account name quoted as Go's %q does.
var targetAccountMissingPattern = regexp.MustCompile(`^enterprise hooks: target account "(?:[^"\\]|\\.)*" does not exist: no such account$`)

// targetAccountMissingError matches the guardian's definitive "no such
// account" resolution error: `enterprise hooks: target account "<name>"
// does not exist: no such account`, and nothing else. The match is on the
// whole message, because other guardian errors can quote text from a
// user's own files.
func targetAccountMissingError(message string) bool {
	return targetAccountMissingPattern.MatchString(strings.TrimSpace(message))
}

// targetHomeUnavailableError matches the guardian's error for a home that
// is not there (CheckUnixTargetHome): the home of a deleted account removed
// with it, for one (GAP-0692).
func targetHomeUnavailableError(message string) bool {
	return strings.Contains(message, "user home ") && strings.Contains(message, " is not available yet")
}

// userHomePathRefusalPatterns are the whole of the per-user worker's
// refusals of one path, without the "enterprise hooks: " prefix: a symbolic
// link ("refusing symlink in hook config path: <path>"), a file where a
// folder belongs or a folder where a file belongs ("hook config parent is
// not a directory: <path>", "hook config path is a directory: <path>"), and
// a folder the worker, which runs as the account, cannot search ("inspect
// hook config parent <path>: lstat <path>: permission denied"), and a hook
// config, or a folder above it, that does not exist ("hook config parent
// missing: <path>", "hook config file missing: <path>"): the agent keeps its
// config there (~/.hermes/config.yaml for Hermes), and an account that has
// not set the agent up has none yet. A managed ensure
// failed with guardian_target_failed for every such account of a shared
// Hermes install (enrollment.agent_prefixes), although the change was
// applied and only those accounts were affected (GAP-2593). The last group
// is the refused path.
var userHomePathRefusalPatterns = []*regexp.Regexp{
	regexp.MustCompile(`^refusing symlink (?:in )?[a-z][a-z ]*: (/.+)$`),
	regexp.MustCompile(`^[a-z][a-z ]* (?:is not a directory|path is a directory|parent missing|file missing): (/.+)$`),
	regexp.MustCompile(`^inspect [a-z][a-z ]* /.+: lstat (/.+): (?:permission denied|not a directory)$`),
}

// userHomePathRefusalWrapper is the per-user worker's wrapper around the
// bootstrap of a connector's missing hook config (enterprisehooks
// installer.go: "bootstrap missing hook config for <connector>: enterprise
// hooks: <refusal>"). The refusal inside it is classified as if it were not
// wrapped: a folder the account made unreadable stops the bootstrap's lstat
// before the strict validate step would (Antigravity ~/.gemini, GAP-0051).
// The first group is the wrapped refusal.
var userHomePathRefusalWrapper = regexp.MustCompile(`^bootstrap missing hook config for [a-z][a-z0-9_-]*: enterprise hooks: (.+)$`)

// userHomePathRefusal reports whether reason is one of those refusals for a
// path strictly inside home, the target account's own home, bare or inside
// userHomePathRefusalWrapper. The match is on the whole reason, because
// other guardian errors can quote text from a user's own files. A refusal of
// the home itself or of a path outside it, and every other error, stays a
// guardian_target_failed.
func userHomePathRefusal(reason, home string) bool {
	home = filepath.Clean(strings.TrimSpace(home))
	if !filepath.IsAbs(home) || home == "/" {
		return false
	}
	if match := userHomePathRefusalWrapper.FindStringSubmatch(reason); match != nil {
		reason = match[1]
	}
	for _, pattern := range userHomePathRefusalPatterns {
		if match := pattern.FindStringSubmatch(reason); match != nil {
			path := match[len(match)-1]
			return filepath.Clean(path) == path && strings.HasPrefix(path, home+"/")
		}
	}
	return false
}

// accountAbsent reports whether the host's own account lookup also finds no
// account named user (getent passwd on Linux, the local directory node on
// macOS). An account that still exists, a lookup that fails, or a name that
// is not a plain account name keeps the target a guardian_target_failed.
// directoryLookupsFailing reports the directory_lookups_failing warning.
func directoryLookupsFailing(warnings []enterprisestatus.Message) bool {
	for _, warning := range warnings {
		if warning.Code == codeDirectoryLookups {
			return true
		}
	}
	return false
}

func (l *lifecycle) accountAbsent(ctx context.Context, user string) bool {
	user = strings.TrimSpace(user)
	if l.env.Accounts == nil || !plainAccountName(user) {
		return false
	}
	if ctx == nil {
		ctx = context.Background()
	}
	lookupCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	_, found, err := l.env.Accounts.Lookup(lookupCtx, user)
	return err == nil && !found
}

// plainAccountName accepts the account names Linux and macOS create: no
// path separator, whitespace or leading dash, bounded length.
func plainAccountName(name string) bool {
	if name == "" || len(name) > 256 || strings.HasPrefix(name, "-") {
		return false
	}
	for _, r := range name {
		if r == '/' || r == '\\' || r == ':' || r <= ' ' || r == 0x7f {
			return false
		}
	}
	return true
}

func unverifiedHookContractError(message string) bool {
	return strings.Contains(message, "is not verified against a known hook contract") ||
		strings.Contains(message, "is not covered by a known hook contract")
}
