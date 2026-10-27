//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
)

// Per-user cleanup on the standalone Unix guardian. When the manifest stops
// enrolling a target the guardian protected (the administrator disabled or
// removed the connector, or the user is no longer enrolled), the gateway
// refuses that user's hooks for the connector, so the registration left in
// the home stops the user's agent. The guardian removes DefenseClaw's own
// registration as that user with the teardown uninstall runs: only
// DefenseClaw's entries go, and files DefenseClaw changed (such as Kiro's
// default agent setting) are restored from its backups. A cleanup that
// cannot run yet (the home is unavailable) or that fails stays in the
// protected cleanup ledger, is retried on every reconcile, and is reported
// by the lifecycle status and verify.

// enterpriseHookUnixTargetSet holds (connector, account) pairs under every
// identifier a row carries, so a manifest row written with only a user
// name, a uid or a home still matches the target it protected.
type enterpriseHookUnixTargetSet map[string]bool

func (s enterpriseHookUnixTargetSet) add(connectorName, userName string, uid int, home string) {
	connectorName = strings.ToLower(strings.TrimSpace(connectorName))
	if connectorName == "" {
		return
	}
	if userName = strings.TrimSpace(userName); userName != "" {
		s[connectorName+"\x00user\x00"+userName] = true
	}
	if uid > 0 {
		s[connectorName+"\x00uid\x00"+strconv.Itoa(uid)] = true
	}
	if home = strings.TrimSpace(home); home != "" {
		s[connectorName+"\x00home\x00"+filepath.Clean(home)] = true
	}
}

func (s enterpriseHookUnixTargetSet) has(entry enterpriseHookUserCleanup) bool {
	connectorName := strings.ToLower(strings.TrimSpace(entry.Connector))
	userName, home := strings.TrimSpace(entry.User), strings.TrimSpace(entry.UserHome)
	return (userName != "" && s[connectorName+"\x00user\x00"+userName]) ||
		(entry.UID > 0 && s[connectorName+"\x00uid\x00"+strconv.Itoa(entry.UID)]) ||
		(home != "" && s[connectorName+"\x00home\x00"+filepath.Clean(home)])
}

func enterpriseHookStandaloneUnixCleanupKey(entry enterpriseHookUserCleanup) string {
	return enterpriseHookProtectedTargetKey(enterpriseHookReconcileRow{
		User: entry.User, UserHome: entry.UserHome, Connector: entry.Connector,
	})
}

func sortEnterpriseHookStandaloneUnixCleanups(entries []enterpriseHookUserCleanup) {
	sort.SliceStable(entries, func(i, j int) bool {
		return enterpriseHookStandaloneUnixCleanupKey(entries[i]) < enterpriseHookStandaloneUnixCleanupKey(entries[j])
	})
}

// planEnterpriseHookStandaloneUnixCleanups returns the cleanups to attempt
// now (due) and the recorded ones to carry unchanged (held). A target the
// previous reconcile protected (the ledger's protected targets, or an
// identity binding for one whose home was pending) that no enabled
// manifest row admits is due. A connector published through vendor
// machine policy is not: its row only records that the uid is enrolled,
// and the guardian installed nothing in that home. A recorded cleanup is
// dropped once the manifest admits the target again and the guardian
// protects it (install owns the registration from then on); while it is
// admitted but not yet protected it is held, so a second revocation before
// that still cleans.
func planEnterpriseHookStandaloneUnixCleanups(
	pending []enterpriseHookUserCleanup,
	protected []enterpriseHookReconcileRow,
	bindings enterpriseHookUnixBindings,
	manifest enterprisehooks.Manifest,
	machinePolicy map[string]struct{},
	now time.Time,
) (due, held []enterpriseHookUserCleanup) {
	admitted := enterpriseHookUnixTargetSet{}
	for _, target := range manifest.Targets {
		if !target.IsEnabled() {
			continue
		}
		uid := 0
		if target.UID != nil {
			uid = *target.UID
		}
		admitted.add(target.Connector, target.User, uid, target.UserHome)
	}
	protectedNow := enterpriseHookUnixTargetSet{}
	for _, row := range protected {
		protectedNow.add(row.Connector, row.User, row.UID, row.UserHome)
	}
	seen := map[string]bool{}
	record := func(entry enterpriseHookUserCleanup) {
		key := enterpriseHookStandaloneUnixCleanupKey(entry)
		if key == "" || seen[key] {
			return
		}
		seen[key] = true
		if admitted.has(entry) {
			held = append(held, entry)
		} else {
			due = append(due, entry)
		}
	}
	for _, entry := range pending {
		if admitted.has(entry) && protectedNow.has(entry) {
			continue
		}
		record(entry)
	}
	recordedAt := now.UTC().Format(time.RFC3339Nano)
	revoked := func(entry enterpriseHookUserCleanup) {
		entry.Connector = strings.ToLower(strings.TrimSpace(entry.Connector))
		entry.User = strings.TrimSpace(entry.User)
		entry.UserHome = filepath.Clean(strings.TrimSpace(entry.UserHome))
		entry.RecordedAt = recordedAt
		if entry.Connector == "" || entry.UID <= 0 || !filepath.IsAbs(entry.UserHome) || admitted.has(entry) {
			return
		}
		record(entry)
	}
	for _, row := range protected {
		entry := enterpriseHookUserCleanup{Connector: row.Connector, User: row.User, UID: row.UID, UserHome: row.UserHome}
		if row.Result == nil {
			// A machine-policy row has no per-user install result: the
			// guardian installed nothing in that home. Its binding must
			// not bring it back below.
			seen[enterpriseHookStandaloneUnixCleanupKey(entry)] = true
			continue
		}
		if entry.Connector == "" {
			entry.Connector = row.Result.Connector
		}
		if dataDir := strings.TrimSpace(row.Result.DataDir); dataDir != "" {
			entry.DataDir = filepath.Clean(dataDir)
		}
		revoked(entry)
	}
	keys := make([]string, 0, len(bindings.Bindings))
	for key := range bindings.Bindings {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		// Binding keys are enterpriseHookProtectedTargetKey values.
		parts := strings.SplitN(key, "\x00", 3)
		if len(parts) != 3 || (parts[1] != "user" && parts[1] != "home") {
			continue
		}
		if _, machine := machinePolicy[parts[0]]; machine {
			continue
		}
		binding := bindings.Bindings[key]
		entry := enterpriseHookUserCleanup{Connector: parts[0], UID: binding.UID, UserHome: binding.Home}
		if parts[1] == "user" {
			entry.User = parts[2]
		}
		revoked(entry)
	}
	sortEnterpriseHookStandaloneUnixCleanups(due)
	sortEnterpriseHookStandaloneUnixCleanups(held)
	return due, held
}

// reconcileEnterpriseHookStandaloneUnixCleanups is the guardian step: plan,
// attempt every due cleanup as its user, log the outcome and persist what
// is still to clean.
func reconcileEnterpriseHookStandaloneUnixCleanups(
	ctx context.Context,
	log io.Writer,
	manifest enterprisehooks.Manifest,
	bindings enterpriseHookUnixBindings,
	machinePolicy map[string]struct{},
	resolver unixidentity.Resolver,
	now time.Time,
) error {
	pending, err := loadEnterpriseHookUserCleanups(cfg.DataDir)
	damaged := err != nil
	if damaged {
		fmt.Fprintf(log, "[hook-guardian] warn: per-user cleanup: %v (replacing it)\n", err)
		pending = nil
	}
	authorization, _, err := loadEnterpriseHookGuardianAuthorization(cfg.DataDir)
	if err != nil {
		// The identity bindings still name the targets protected before.
		fmt.Fprintf(log, "[hook-guardian] warn: per-user cleanup: %v\n", err)
	}
	due, held := planEnterpriseHookStandaloneUnixCleanups(pending, authorization.ProtectedTargets, bindings, manifest, machinePolicy, now)
	known := map[string]bool{}
	for _, entry := range pending {
		known[enterpriseHookUserCleanupLabel(entry)] = true
	}
	// A cleanup retired as home gone removed nothing; it already said so.
	retired := map[string]bool{}
	remaining, result := runEnterpriseHookUserCleanups(ctx, due, func(ctx context.Context, entry enterpriseHookUserCleanup) (enterpriseHookUserCleanupOutcome, error) {
		outcome, err := attemptEnterpriseHookStandaloneUnixCleanup(ctx, log, entry, resolver)
		if errors.Is(err, errEnterpriseHookCleanupHomeGone) {
			retired[enterpriseHookUserCleanupLabel(entry)] = true
		}
		return outcome, err
	}, now)
	remaining = append(remaining, held...)
	sortEnterpriseHookStandaloneUnixCleanups(remaining)
	for _, label := range result.Removed {
		if !retired[label] {
			fmt.Fprintf(log, "[hook-guardian] %s: no longer enrolled; per-user cleanup done\n", label)
		}
	}
	for _, label := range result.Pending {
		if !known[label] {
			fmt.Fprintf(log, "[hook-guardian] %s: no longer enrolled; the home is not available, so removing DefenseClaw's registration is recorded and retried\n", label)
		}
	}
	for _, failure := range result.Failed {
		fmt.Fprintf(log, "[hook-guardian] warn: per-user cleanup of %s (will retry)\n", failure)
	}
	if !damaged && sameEnterpriseHookUserCleanups(pending, remaining) {
		return nil
	}
	return saveEnterpriseHookUserCleanups(cfg.DataDir, remaining, now)
}

// errEnterpriseHookCleanupHomeGone comes with a done outcome only when the
// directory gives the account no home and its recorded home is gone.
// Nothing was removed, and nothing is left to remove.
var errEnterpriseHookCleanupHomeGone = errors.New("the recorded home no longer exists")

// enterpriseHookCleanupAccountGone confirms, outside this long-running
// process, that an account a lookup still found has no directory record
// (unixidentity.AccountRecordGone). Tests replace it.
var enterpriseHookCleanupAccountGone = unixidentity.AccountRecordGone

// enterpriseHookRecordedHomeGone reports a recorded home that definitively
// does not exist: its parent directory answers, holds other entries, and
// the home itself is not there. A home that does not answer in time, or
// whose parent is missing too or empty (an unmounted volume: its mount
// point stays as an empty folder, GAP-0443), is not gone. A cleanup is
// retired on this evidence only when the directory also gives the account
// no home.
var enterpriseHookRecordedHomeGone = func(home string) bool {
	home = filepath.Clean(home)
	if !filepath.IsAbs(home) || home == filepath.Dir(home) {
		return false
	}
	parent, err := enterprisehooks.BoundedLstat(filepath.Dir(home), enterpriseHookHomeCheckTimeout)
	if err != nil || !parent.IsDir() {
		return false
	}
	_, err = enterprisehooks.BoundedLstat(home, enterpriseHookHomeCheckTimeout)
	if !errors.Is(err, os.ErrNotExist) {
		return false
	}
	others, err := enterprisehooks.BoundedDirHasEntries(filepath.Dir(home), enterpriseHookHomeCheckTimeout)
	return err == nil && others
}

// enterpriseHookRecordedHomeMoved reports whether a re-homed account's
// recorded home counts as moved: it is gone, or it is an empty folder (an
// rsync, then its contents deleted). A recorded home that still holds any
// entry, or cannot be read, is a copy: the cleanup ran in it too and found
// it clean, and the audit line must not call it a move (rel-1-0-3
// GAP-0257).
func enterpriseHookRecordedHomeMoved(home string) bool {
	if enterpriseHookRecordedHomeGone(home) {
		return true
	}
	info, err := enterprisehooks.BoundedLstat(home, enterpriseHookHomeCheckTimeout)
	if err != nil || !info.IsDir() {
		return false
	}
	dir, err := os.Open(home)
	if err != nil {
		return false
	}
	defer dir.Close()
	names, err := dir.Readdirnames(1)
	return len(names) == 0 && errors.Is(err, io.EOF)
}

// enterpriseHookDirectoryNoHome reports a directory home that is no home:
// what the directory gives a removed or disabled account (a removed macOS
// AD mobile account answers with /var/empty), not a place a user's agent
// runs from.
func enterpriseHookDirectoryNoHome(home string) bool {
	home = strings.TrimSpace(home)
	if !filepath.IsAbs(home) {
		return true
	}
	switch filepath.Clean(home) {
	case "/var/empty", "/dev/null", "/nonexistent":
		return true
	}
	return false
}

// The standalone resolver treats an empty directory home as an omitted
// manifest home. For a recorded cleanup, capture the directory's actual
// answer so that an empty home retires a cleanup only when the recorded
// home is definitely gone. Otherwise the recorded home remains the target.
type enterpriseHookCleanupHomeResolver struct {
	unixidentity.Resolver
	directoryHome string
	lookedUp      bool
}

func (r *enterpriseHookCleanupHomeResolver) LookupUser(name string) (unixidentity.Account, error) {
	account, err := r.Resolver.LookupUser(name)
	if err == nil {
		r.directoryHome, r.lookedUp = account.Home, true
	}
	return account, err
}

func (r *enterpriseHookCleanupHomeResolver) LookupUID(uid int) (unixidentity.Account, error) {
	account, err := r.Resolver.LookupUID(uid)
	if err == nil {
		r.directoryHome, r.lookedUp = account.Home, true
	}
	return account, err
}

// enterpriseHookCleanupHomeKeptError is a cleanup of an account the
// directory now gives a no-home path (it looks removed) whose recorded home
// is not gone: its folder was kept (sysadminctl -deleteUser -keepHome, dscl .
// -delete), or did not answer. Nothing proves DefenseClaw's registration
// went, and no worker runs as an account without a home, so the guardian
// keeps retrying and warning it, while an uninstall warns for it and goes on
// (GAP-0553). A re-homed live account (its directory home is a real path) is
// not this error.
type enterpriseHookCleanupHomeKeptError struct {
	name, home, directoryHome string
}

func (e *enterpriseHookCleanupHomeKeptError) Error() string {
	return fmt.Sprintf("enterprise hooks: target %q home %s no longer matches the directory home %s, which is no home: the account looks removed, but its recorded home is not gone and may still hold DefenseClaw's entries", e.name, e.home, e.directoryHome)
}

// enterpriseHookCleanupOldHomeKeptError means the current home was cleaned,
// but the recorded home was not confirmed gone and cannot be trusted for a
// second worker. The guardian keeps the row; remove-all reports it pending.
type enterpriseHookCleanupOldHomeKeptError struct {
	name, connector, home, currentHome, reason string
}

func (e *enterpriseHookCleanupOldHomeKeptError) Error() string {
	return fmt.Sprintf("enterprise hooks: recorded home %s of account %q may still hold DefenseClaw's %s entries: the account was re-homed to %s and cleaned there, but the recorded home still exists or cannot be confirmed gone and cannot be checked or trusted (%s); remove the entries from the %s config in %s, or delete that home if unused; fix its owner or permissions to let the guardian clean it",
		e.home, e.name, e.connector, e.currentHome, e.reason, e.connector, e.home)
}

// enterpriseHookCleanupUnverifiedError keeps a re-homed row when a worker's
// report does not prove that it acted inside its assigned home, or the
// current home still has DefenseClaw entries after one immediate retry.
type enterpriseHookCleanupUnverifiedError struct {
	changed    *enterpriseHookTargetHomeChangedError
	connector  string
	dataDir    string
	home       string
	path       string
	configPath string
	reason     string
}

func (e *enterpriseHookCleanupUnverifiedError) Unwrap() error { return e.changed }

func (e *enterpriseHookCleanupUnverifiedError) Error() string {
	location := "in the home " + e.home
	if e.configPath != "" && e.configPath != e.home {
		location = "at " + e.configPath
	}
	return fmt.Sprintf("%s: cleanup cannot be verified at %s (%s); remove DefenseClaw's entries from that agent's config %s, delete the stale copied receipt under %s if it keeps naming the other home, and rerun",
		e.changed, e.path, e.reason, location, filepath.Join(e.dataDir, "connector_backups", e.connector)+string(filepath.Separator))
}

func newEnterpriseHookCleanupUnverifiedError(changed *enterpriseHookTargetHomeChangedError, entry enterpriseHookUserCleanup,
	home, dataDir, path, reason string, report enterpriseHookWorkerTargetResult,
) *enterpriseHookCleanupUnverifiedError {
	configPath := home
	for _, candidate := range report.CleanedPaths {
		if enterpriseHookWorkerPathWithin(home, candidate) {
			configPath = candidate
			break
		}
	}
	return &enterpriseHookCleanupUnverifiedError{changed: changed, connector: entry.Connector,
		dataDir: dataDir, home: home, path: path, configPath: configPath, reason: reason}
}

// enterpriseHookCleanupReportProblem names why a worker's report does not
// prove its home clean: no path report, a path outside that home, or a
// DefenseClaw entry still there. Both the current and the recorded home of a
// re-homed row must pass it, since the agent can load either (GAP-0625).
func enterpriseHookCleanupReportProblem(report enterpriseHookWorkerTargetResult, home string) (string, string) {
	if !report.PathsReported {
		reason := "the worker did not report the paths it found"
		if report.Unverified != "" {
			reason += ": " + report.Unverified
		}
		return home, reason
	}
	for _, path := range report.CleanedPaths {
		if !enterpriseHookWorkerPathWithin(home, path) {
			return path, "the worker reported a path outside the home it cleaned"
		}
	}
	if report.Remaining != "" {
		path := home
		if len(report.CleanedPaths) != 0 {
			path = report.CleanedPaths[0]
		}
		return path, "DefenseClaw entries remain: " + report.Remaining
	}
	return "", ""
}

func enterpriseHookCleanupFailurePath(report enterpriseHookWorkerTargetResult, home string) string {
	if path, _ := enterpriseHookCleanupReportProblem(report, home); path != "" {
		return path
	}
	if len(report.CleanedPaths) != 0 {
		return report.CleanedPaths[0]
	}
	return home
}

// attemptEnterpriseHookStandaloneUnixCleanup removes one registration in
// the per-user worker, with the user's credentials. An unavailable home or
// directory is pending. An account that no longer exists (or whose name now
// belongs to another uid) leaves no one to act as and no one whose agent
// runs those hooks, so its entry is dropped: the enumerator revokes such a
// row only after repeated definitive "no such account" answers. An entry
// is also retired when the directory gives the account no home and its
// recorded home is gone: the registration went with that home, and a retry
// could never succeed (GAP-0543). It is done with
// errEnterpriseHookCleanupHomeGone, so an uninstall reports it with a
// warning and goes on (GAP-0553). An entry whose directory home is no home
// while its recorded home is not gone fails with
// *enterpriseHookCleanupHomeKeptError, which an uninstall also only warns.
// A live account re-homed to a trusted real path is cleaned in its current
// home and also in its recorded home when that home still exists and is
// trusted. An incomplete cleanup in either home keeps the row with the
// affected path in its warning. An existing recorded home that cannot be
// trusted also keeps the row. An untrusted or unavailable new home keeps it
// fail-closed until the account is removed, its uid changes, or its home is
// fixed.
func attemptEnterpriseHookStandaloneUnixCleanup(
	ctx context.Context,
	log io.Writer,
	entry enterpriseHookUserCleanup,
	resolver unixidentity.Resolver,
) (enterpriseHookUserCleanupOutcome, error) {
	home := filepath.Clean(strings.TrimSpace(entry.UserHome))
	uid := entry.UID
	homeResolver := &enterpriseHookCleanupHomeResolver{Resolver: resolver}
	account, pendingReason, err := resolveEnterpriseHookStandaloneAccount(
		enterprisehooks.ManifestTarget{User: strings.TrimSpace(entry.User), UserHome: home, UID: &uid},
		homeResolver,
	)
	var homeChanged *enterpriseHookTargetHomeChangedError
	errors.As(err, &homeChanged)
	recordedHomeGone := false
	if err == nil && pendingReason == "" && homeResolver.lookedUp &&
		strings.TrimSpace(homeResolver.directoryHome) == "" && filepath.IsAbs(home) {
		recordedHomeGone = enterpriseHookRecordedHomeGone(home)
		if recordedHomeGone {
			homeChanged = &enterpriseHookTargetHomeChangedError{
				name: firstNonEmpty(account.User, strings.TrimSpace(entry.User)), home: home, directoryHome: homeResolver.directoryHome,
			}
		}
	}
	if homeChanged != nil && enterpriseHookDirectoryNoHome(homeChanged.directoryHome) && !recordedHomeGone {
		recordedHomeGone = enterpriseHookRecordedHomeGone(homeChanged.home)
	}
	switch {
	case errors.Is(err, errEnterpriseHookTargetNotFound), errors.Is(err, errEnterpriseHookTargetUIDChanged):
		fmt.Fprintf(log, "[hook-guardian] %s: %v; nothing to remove as that user\n", enterpriseHookUserCleanupLabel(entry), err)
		return enterpriseHookUserCleanupDone, nil
	case homeChanged != nil && enterpriseHookDirectoryNoHome(homeChanged.directoryHome) && recordedHomeGone:
		fmt.Fprintf(log, "[hook-guardian] %s: home gone: the recorded home %s no longer exists and the directory gives no home (%s); the cleanup is retired, as nothing is left to remove\n",
			enterpriseHookUserCleanupLabel(entry), homeChanged.home, homeChanged.directoryHome)
		return enterpriseHookUserCleanupDone, errEnterpriseHookCleanupHomeGone
	case homeChanged != nil && enterpriseHookDirectoryNoHome(homeChanged.directoryHome):
		return enterpriseHookUserCleanupFailed, &enterpriseHookCleanupHomeKeptError{name: homeChanged.name, home: homeChanged.home, directoryHome: homeChanged.directoryHome}
	case homeChanged != nil:
		// Resolve again against the directory's current home. This repeats
		// the uid and absolute-home checks after the first lookup; a name
		// reassignment or a second home change cannot select another user.
		account, pendingReason, err = resolveEnterpriseHookStandaloneAccount(
			enterprisehooks.ManifestTarget{User: strings.TrimSpace(entry.User), UserHome: homeChanged.directoryHome, UID: &uid},
			resolver,
		)
		if err != nil {
			return enterpriseHookUserCleanupFailed, enterpriseHookRehomedCleanupError(homeChanged, err.Error())
		}
		if pendingReason != "" {
			return enterpriseHookUserCleanupFailed, enterpriseHookRehomedCleanupError(homeChanged, pendingReason)
		}
	case err != nil:
		return enterpriseHookUserCleanupFailed, err
	case pendingReason != "":
		return enterpriseHookUserCleanupPending, nil
	}
	check := enterpriseHookCheckHome(account.Home, account.UID)
	if homeChanged != nil && check.State != enterprisehooks.HomeAvailable {
		return enterpriseHookUserCleanupFailed, enterpriseHookRehomedCleanupError(homeChanged, check.Reason)
	}
	switch check.State {
	case enterprisehooks.HomePending:
		if filepath.Clean(account.Home) == home && enterpriseHookRecordedHomeGone(home) &&
			enterpriseHookCleanupAccountGone(ctx, account.User) {
			// This process's lookup found the account, but a fresh directory
			// read has no record of it and its home is gone: it was deleted,
			// and the lookup answered from a stale per-process cache (macOS,
			// rel-1-0-5 GAP-0029). Waiting for the home to come back would
			// keep the cleanup open forever.
			fmt.Fprintf(log, "[hook-guardian] %s: no such account (a fresh directory read has no record of %s, and its recorded home %s is gone); nothing to remove as that user\n",
				enterpriseHookUserCleanupLabel(entry), account.User, home)
			return enterpriseHookUserCleanupDone, nil
		}
		return enterpriseHookUserCleanupPending, nil
	case enterprisehooks.HomeUntrusted:
		return enterpriseHookUserCleanupFailed, errors.New("enterprise hooks: " + check.Reason)
	}
	dataDir := strings.TrimSpace(entry.DataDir)
	if dataDir == "" {
		dataDir = filepath.Join(account.Home, ".defenseclaw")
	} else if homeChanged != nil && homeChanged.home != filepath.Dir(homeChanged.home) {
		// A moved home carries its per-user state with it. A data directory
		// outside the recorded home remains as recorded for worker validation.
		rel, relErr := filepath.Rel(homeChanged.home, dataDir)
		if relErr == nil && !filepath.IsAbs(rel) && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			dataDir = filepath.Join(account.Home, rel)
		}
	}
	outcome, report, err := runEnterpriseHookStandaloneCleanupWorker(ctx, entry, account, dataDir)
	if outcome != enterpriseHookUserCleanupDone {
		if err != nil && homeChanged != nil {
			return outcome, newEnterpriseHookCleanupUnverifiedError(homeChanged, entry, account.Home, dataDir,
				enterpriseHookCleanupFailurePath(report, account.Home), "current-home cleanup failed: "+err.Error(), report)
		}
		return outcome, err
	}
	if homeChanged != nil {
		path, reason := enterpriseHookCleanupReportProblem(report, account.Home)
		if reason != "" && report.PathsReported {
			// A copied receipt may have just been consumed in the other home.
			// The next pass must use the current home's own config path.
			outcome, report, err = runEnterpriseHookStandaloneCleanupWorker(ctx, entry, account, dataDir)
			if outcome != enterpriseHookUserCleanupDone {
				if outcome == enterpriseHookUserCleanupPending {
					return outcome, err
				}
				if err != nil {
					reason = err.Error()
				}
				return enterpriseHookUserCleanupFailed, newEnterpriseHookCleanupUnverifiedError(homeChanged, entry,
					account.Home, dataDir, path, reason, report)
			}
			path, reason = enterpriseHookCleanupReportProblem(report, account.Home)
		}
		if reason != "" {
			return enterpriseHookUserCleanupFailed, newEnterpriseHookCleanupUnverifiedError(homeChanged, entry,
				account.Home, dataDir, path, reason, report)
		}
		if !enterpriseHookRecordedHomeGone(homeChanged.home) {
			oldCheck := enterpriseHookCheckHome(homeChanged.home, entry.UID)
			if oldCheck.State != enterprisehooks.HomeAvailable {
				return enterpriseHookUserCleanupFailed, &enterpriseHookCleanupOldHomeKeptError{
					name: account.User, connector: strings.ToLower(strings.TrimSpace(entry.Connector)),
					home: homeChanged.home, currentHome: account.Home, reason: oldCheck.Reason,
				}
			}
			recordedAccount := account
			recordedAccount.Home = homeChanged.home
			recordedDataDir := strings.TrimSpace(entry.DataDir)
			if recordedDataDir == "" {
				recordedDataDir = filepath.Join(recordedAccount.Home, ".defenseclaw")
			}
			outcome, report, err = runEnterpriseHookStandaloneCleanupWorker(ctx, entry, recordedAccount, recordedDataDir)
			if outcome != enterpriseHookUserCleanupDone {
				if err != nil {
					return outcome, newEnterpriseHookCleanupUnverifiedError(homeChanged, entry, recordedAccount.Home,
						recordedDataDir, enterpriseHookCleanupFailurePath(report, recordedAccount.Home), "recorded-home cleanup failed: "+err.Error(), report)
				}
				return outcome, err
			}
			path, reason = enterpriseHookCleanupReportProblem(report, recordedAccount.Home)
			if reason != "" && report.PathsReported {
				outcome, report, err = runEnterpriseHookStandaloneCleanupWorker(ctx, entry, recordedAccount, recordedDataDir)
				if outcome != enterpriseHookUserCleanupDone {
					if outcome == enterpriseHookUserCleanupPending {
						return outcome, err
					}
					if err != nil {
						reason = err.Error()
					}
					return enterpriseHookUserCleanupFailed, newEnterpriseHookCleanupUnverifiedError(homeChanged, entry,
						recordedAccount.Home, recordedDataDir, path, reason, report)
				}
				path, reason = enterpriseHookCleanupReportProblem(report, recordedAccount.Home)
			}
			if reason != "" {
				return enterpriseHookUserCleanupFailed, newEnterpriseHookCleanupUnverifiedError(homeChanged, entry,
					recordedAccount.Home, recordedDataDir, path, reason, report)
			}
		}
		if enterpriseHookRecordedHomeMoved(homeChanged.home) {
			fmt.Fprintf(log, "[hook-guardian] %s: the account's home moved from %s to %s (the recorded home is gone or empty); per-user cleanup ran in the current home\n",
				enterpriseHookUserCleanupLabel(entry), homeChanged.home, account.Home)
		} else {
			fmt.Fprintf(log, "[hook-guardian] %s: the account's home changed from %s to %s, and the recorded home still holds files, so this is a copy, not a move; per-user cleanup ran in both homes and found both clean\n",
				enterpriseHookUserCleanupLabel(entry), homeChanged.home, account.Home)
		}
	}
	return enterpriseHookUserCleanupDone, nil
}

// runEnterpriseHookStandaloneCleanupWorker sends the same remove request and
// interprets the same response for a current or recorded home.
// A current-home pass of a re-homed account (account.Home is not the
// recorded home) names the recorded home as the previous one, so receipts
// copied from it act on this home's copies only.
func runEnterpriseHookStandaloneCleanupWorker(ctx context.Context, entry enterpriseHookUserCleanup, account enterpriseHookWorkerAccount, dataDir string) (enterpriseHookUserCleanupOutcome, enterpriseHookWorkerTargetResult, error) {
	previousHome := ""
	if recorded := filepath.Clean(strings.TrimSpace(entry.UserHome)); filepath.IsAbs(recorded) && recorded != filepath.Clean(account.Home) {
		previousHome = recorded
	}
	response, err := enterpriseHookWorkerRunner(ctx, account, enterpriseHookWorkerRequest{
		Operation:  enterpriseHookWorkerOpApply,
		Standalone: true,
		Targets: []enterpriseHookWorkerTarget{{
			Mode: enterpriseHookWorkerModeRemove,
			Options: enterpriseHookWorkerOptions{
				ConnectorName: strings.ToLower(strings.TrimSpace(entry.Connector)),
				UserHome:      account.Home,
				OwnerUID:      account.UID,
				OwnerGID:      account.GID,
				DataDir:       dataDir,
				PreviousHome:  previousHome,
			},
		}},
	})
	if err != nil {
		return enterpriseHookUserCleanupFailed, enterpriseHookWorkerTargetResult{}, err
	}
	for _, result := range response.Targets {
		if result.Index != 0 {
			continue
		}
		if err := validateEnterpriseHookWorkerRemoveReport(result); err != nil {
			return enterpriseHookUserCleanupFailed, result, err
		}
		switch {
		case result.Pending:
			return enterpriseHookUserCleanupPending, result, nil
		case result.OK:
			return enterpriseHookUserCleanupDone, result, nil
		default:
			return enterpriseHookUserCleanupFailed, result, errors.New(boundedString(result.Error, 256))
		}
	}
	if response.Error != "" {
		return enterpriseHookUserCleanupFailed, enterpriseHookWorkerTargetResult{}, errors.New(boundedString(response.Error, 256))
	}
	return enterpriseHookUserCleanupFailed, enterpriseHookWorkerTargetResult{}, errEnterpriseHookWorkerNoResult
}

func enterpriseHookRehomedCleanupError(changed *enterpriseHookTargetHomeChangedError, reason string) error {
	if reason == "" {
		reason = "the current home is not available or trusted"
	}
	reason = strings.TrimPrefix(reason, "user home "+changed.directoryHome+" ")
	return fmt.Errorf("%w: fix the account's home to an existing account-owned directory without symlinks or group/other write, or remove the account, then rerun; current home check: %s",
		changed, reason)
}
