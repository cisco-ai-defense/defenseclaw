//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
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
	remaining, result := runEnterpriseHookUserCleanups(ctx, due, func(ctx context.Context, entry enterpriseHookUserCleanup) (enterpriseHookUserCleanupOutcome, error) {
		return attemptEnterpriseHookStandaloneUnixCleanup(ctx, log, entry, resolver)
	}, now)
	remaining = append(remaining, held...)
	sortEnterpriseHookStandaloneUnixCleanups(remaining)
	for _, label := range result.Removed {
		fmt.Fprintf(log, "[hook-guardian] %s: no longer enrolled; per-user cleanup done\n", label)
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

// attemptEnterpriseHookStandaloneUnixCleanup removes one registration in
// the per-user worker, with the user's credentials. An unavailable home or
// directory is pending. An account that no longer exists (or whose name now
// belongs to another uid) leaves no one to act as and no one whose agent
// runs those hooks, so its entry is dropped: the enumerator revokes such a
// row only after repeated definitive "no such account" answers.
func attemptEnterpriseHookStandaloneUnixCleanup(
	ctx context.Context,
	log io.Writer,
	entry enterpriseHookUserCleanup,
	resolver unixidentity.Resolver,
) (enterpriseHookUserCleanupOutcome, error) {
	home := filepath.Clean(strings.TrimSpace(entry.UserHome))
	uid := entry.UID
	account, pendingReason, err := resolveEnterpriseHookStandaloneAccount(
		enterprisehooks.ManifestTarget{User: strings.TrimSpace(entry.User), UserHome: home, UID: &uid},
		resolver,
	)
	switch {
	case errors.Is(err, errEnterpriseHookTargetNotFound), errors.Is(err, errEnterpriseHookTargetUIDChanged):
		fmt.Fprintf(log, "[hook-guardian] %s: %v; nothing to remove as that user\n", enterpriseHookUserCleanupLabel(entry), err)
		return enterpriseHookUserCleanupDone, nil
	case err != nil:
		return enterpriseHookUserCleanupFailed, err
	case pendingReason != "":
		return enterpriseHookUserCleanupPending, nil
	}
	switch check := enterpriseHookCheckHome(account.Home, account.UID); check.State {
	case enterprisehooks.HomePending:
		return enterpriseHookUserCleanupPending, nil
	case enterprisehooks.HomeUntrusted:
		return enterpriseHookUserCleanupFailed, errors.New("enterprise hooks: " + check.Reason)
	}
	dataDir := strings.TrimSpace(entry.DataDir)
	if dataDir == "" {
		dataDir = filepath.Join(account.Home, ".defenseclaw")
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
			},
		}},
	})
	if err != nil {
		return enterpriseHookUserCleanupFailed, err
	}
	for _, result := range response.Targets {
		if result.Index != 0 {
			continue
		}
		switch {
		case result.Pending:
			return enterpriseHookUserCleanupPending, nil
		case result.OK:
			return enterpriseHookUserCleanupDone, nil
		default:
			return enterpriseHookUserCleanupFailed, errors.New(boundedString(result.Error, 256))
		}
	}
	if response.Error != "" {
		return enterpriseHookUserCleanupFailed, errors.New(boundedString(response.Error, 256))
	}
	return enterpriseHookUserCleanupFailed, errEnterpriseHookWorkerNoResult
}
