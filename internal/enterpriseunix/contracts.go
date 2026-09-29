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
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
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
// where a folder belongs (or a folder where a file belongs), or a folder the
// account made unreadable. Only that account is affected, and it could have
// made the change itself, so it is a warning: verify, MDM detection and
// security_complete do not fail on it. The guardian protects the target
// again at its next reconcile after the path is fixed.
const codeGuardianTargetUserPath = "guardian_target_user_path"

// guardianStateFile is the guardian state the gateway reads in DataDir.
const guardianStateFile = "hook_guardian_state.json"

var unverifiedVersionPattern = regexp.MustCompile(`agent version "([^"]*)"`)

// describeHookContracts reports every guardian target the guardian could
// not protect (an unverified hook contract gets its own code) and marks the
// deployment security-incomplete: an unprotected agent must never look like
// a healthy deployment. A target refused only because of a path in its
// account's own home is reported for that account without marking the
// deployment incomplete.
func (l *lifecycle) describeHookContracts(ctx context.Context) {
	env, r := l.env, l.result
	data, err := readBounded(env.P(filepath.Join(env.Layout.DataDir, guardianStateFile)), 4<<20)
	if err != nil {
		return
	}
	var state struct {
		Results []struct {
			User      string `json:"user"`
			UserHome  string `json:"user_home"`
			Connector string `json:"connector"`
			OK        bool   `json:"ok"`
			Error     string `json:"error"`
		} `json:"results"`
	}
	if json.Unmarshal(data, &state) != nil {
		return
	}
	var unverified, failed, removed, userPaths []string
	for _, result := range state.Results {
		if result.OK || strings.TrimSpace(result.Error) == "" {
			continue
		}
		if targetAccountMissingError(result.Error) && l.accountAbsent(ctx, result.User) {
			removed = append(removed, fmt.Sprintf(
				"%s for user %s: the account no longer exists (the directory answers \"no such account\"); the enumerator removes this target after %d consecutive definitive misses, one per enumeration cycle",
				result.Connector, result.User, enterprisehooks.UnixRevokeAfterMisses))
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
	sort.Strings(removed)
	for _, message := range removed {
		r.AddWarning(codeGuardianTargetAccountRemoved, message)
	}
	sort.Strings(userPaths)
	for _, message := range userPaths {
		r.AddWarning(codeGuardianTargetUserPath, message)
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
	r.SecurityComplete = false
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
// reads the guardian as not ready.
func (l *lifecycle) awaitGuardianReport(ctx context.Context, since time.Time) {
	env, r := l.env, l.result
	targets := 0
	if manifest, err := enterprisehooks.LoadManifest(env.P(env.Layout.ManifestPath)); err == nil {
		targets = len(manifest.Targets)
	}
	deadline := env.Now().Add(env.GuardianReportTimeout)
	for {
		if updated, ok := l.guardianReportedAt(); ok && !updated.Before(since) {
			return
		}
		if !env.Now().Before(deadline) {
			if targets > 0 {
				r.AddWarning(codeGuardianReportPending, fmt.Sprintf(
					"the hook guardian has not reported on its %d manifest targets since this change, so their protection is not confirmed yet; run `%s` in a minute to see it",
					targets, env.lifecycleCommand("status")))
			}
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(env.PollInterval):
		}
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

// describeUnprotectedAgents reports the agents the enumerator found
// installed but could not enroll (its unprotected-agents record next to the
// manifest) and marks the deployment security-incomplete.
func (l *lifecycle) describeUnprotectedAgents() {
	env, r := l.env, l.result
	data, err := readBounded(env.P(enterprisehooks.UnprotectedAgentsPath(env.Layout.ManifestPath)), enterprisehooks.UnprotectedAgentsMaxBytes)
	if err != nil {
		return
	}
	agents, err := enterprisehooks.ParseUnprotectedAgents(data)
	if err != nil {
		r.AddWarning(codeAgentUnprotected, "the enumerator's unprotected-agents record is unreadable: "+err.Error())
		r.SecurityComplete = false
		return
	}
	for _, agent := range agents {
		r.AddWarning(agent.Code, agent.Message())
	}
	if len(agents) > 0 {
		r.SecurityComplete = false
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
// user's own files. A directory that cannot answer produces a different
// error, which stays a guardian_target_failed.
func targetAccountMissingError(message string) bool {
	return targetAccountMissingPattern.MatchString(strings.TrimSpace(message))
}

// userHomePathRefusalPatterns are the whole of the per-user worker's
// refusals of one path, without the "enterprise hooks: " prefix: a symbolic
// link ("refusing symlink in hook config path: <path>"), a file where a
// folder belongs or a folder where a file belongs ("hook config parent is
// not a directory: <path>", "hook config path is a directory: <path>"), and
// a folder the worker, which runs as the account, cannot search ("inspect
// hook config parent <path>: lstat <path>: permission denied"). The last
// group is the refused path.
var userHomePathRefusalPatterns = []*regexp.Regexp{
	regexp.MustCompile(`^refusing symlink (?:in )?[a-z][a-z ]*: (/.+)$`),
	regexp.MustCompile(`^[a-z][a-z ]* (?:is not a directory|path is a directory): (/.+)$`),
	regexp.MustCompile(`^inspect [a-z][a-z ]* /.+: lstat (/.+): (?:permission denied|not a directory)$`),
}

// userHomePathRefusal reports whether reason is one of those refusals for a
// path strictly inside home, the target account's own home. The match is on
// the whole reason, because other guardian errors can quote text from a
// user's own files. A refusal of the home itself or of a path outside it,
// and every other error, stays a guardian_target_failed.
func userHomePathRefusal(reason, home string) bool {
	home = filepath.Clean(strings.TrimSpace(home))
	if !filepath.IsAbs(home) || home == "/" {
		return false
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
